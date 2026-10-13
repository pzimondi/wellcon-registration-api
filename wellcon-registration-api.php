<?php
/**
 * Plugin Name: WellCON Registration API
 * Description: Lets external developers submit attendee registrations (1 or many tickets) to MyWellCon.com. POST /wp-json/wellcon/v1/registrations
 */

use SMPLFY\cryoconportal\AddAttendeeOutsideSystemEntity;
use SMPLFY\cryoconportal\Roles;
use SMPLFY\cryoconportal\TicketTypes;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// The core plugin hands over its objects (one do_action line in DependencyFactory.php).
add_action( 'wellcon_purchase_completed_ready', function ( $purchaseCompleted, $outsideRepo ) {
	wellcon_api_deps( [ 'purchase' => $purchaseCompleted, 'outside' => $outsideRepo ] );
}, 10, 2 );

function wellcon_api_deps( $set = null ) {
	static $deps = [];
	if ( $set ) {
		$deps = $set;
	}
	return $deps;
}

function wellcon_api_log( string $message, $data = null ): void {
	if ( class_exists( '\SmplfyCore\SMPLFY_Log' ) ) {
		\SmplfyCore\SMPLFY_Log::info( $message, $data );
	}
}

// API keys: name => sha256 hash (the plain key is shown once, at creation).
// Username from email; appends a number if taken (two emails can strip to the same login).
function wellcon_api_unique_login( string $email ): string {
	$base  = sanitize_user( str_replace( "@", "", $email ), true );
	$login = $base;
	$i     = 1;
	while ( username_exists( $login ) ) {
		$login = $base . $i++;
	}
	return $login;
}

function wellcon_api_keys(): array {
	return (array) get_option( 'wellcon_api_keys', [] );
}

function wellcon_api_source_for_key( string $key ): ?string {
	if ( $key === '' ) {
		return null;
	}
	$hash = hash( 'sha256', $key );
	foreach ( wellcon_api_keys() as $name => $stored ) {
		if ( hash_equals( (string) $stored, $hash ) ) {
			return (string) $name;
		}
	}
	return null;
}

function wellcon_api_check_key( WP_REST_Request $request ) {
	if ( wellcon_api_source_for_key( (string) $request->get_header( 'x_api_key' ) ) === null ) {
		return new WP_Error( 'unauthorized', 'Invalid or missing API key.', [ 'status' => 401 ] );
	}
	return true;
}

add_action( 'rest_api_init', function () {
	register_rest_route( 'wellcon/v1', '/registrations', [
		'methods'             => 'POST',
		'callback'            => 'wellcon_api_create_registration',
		'permission_callback' => 'wellcon_api_check_key',
	] );
	register_rest_route( 'wellcon/v1', '/ticket-types', [
		'methods'             => 'GET',
		'callback'            => function () {
			return [ 'ticket_types' => [ TicketTypes::EXPO, TicketTypes::GENERAL_ADMISSION, TicketTypes::VIP ] ];
		},
		'permission_callback' => 'wellcon_api_check_key',
	] );
} );

function wellcon_api_error( string $code, string $message, int $status = 400 ): WP_Error {
	return new WP_Error( $code, $message, [ 'status' => $status ] );
}

function wellcon_api_create_registration( WP_REST_Request $request ) {
	$source = wellcon_api_source_for_key( (string) $request->get_header( 'x_api_key' ) );
	$deps   = wellcon_api_deps();
	if ( empty( $deps['purchase'] ) ) {
		return wellcon_api_error( 'unavailable', 'Registration service is not ready.', 503 );
	}

	$body  = (array) $request->get_json_params();
	$buyer = (array) ( $body['buyer'] ?? [] );
	$ref   = trim( (string) ( $body['external_ref'] ?? '' ) );
	$email = sanitize_email( (string) ( $buyer['email'] ?? '' ) );
	$first = sanitize_text_field( (string) ( $buyer['first_name'] ?? '' ) );
	$last  = sanitize_text_field( (string) ( $buyer['last_name'] ?? '' ) );
	$phone = sanitize_text_field( (string) ( $buyer['phone'] ?? '' ) );

	if ( $ref === '' || strlen( $ref ) > 100 ) {
		return wellcon_api_error( 'invalid_ref', 'external_ref is required (max 100 characters).' );
	}
	if ( ! is_email( $email ) || $first === '' || $last === '' ) {
		return wellcon_api_error( 'invalid_buyer', 'buyer.email, buyer.first_name and buyer.last_name are required.' );
	}

	$counts = [ TicketTypes::EXPO => 0, TicketTypes::GENERAL_ADMISSION => 0, TicketTypes::VIP => 0 ];
	foreach ( (array) ( $body['tickets'] ?? [] ) as $ticket ) {
		$ticket = (array) $ticket;
		$type   = strtoupper( str_replace( [ ' ', '-' ], '_', (string) ( $ticket['type'] ?? '' ) ) );
		$qty    = (int) ( $ticket['quantity'] ?? 0 );
		if ( ! isset( $counts[ $type ] ) || $qty < 1 || $qty > 50 ) {
			return wellcon_api_error( 'invalid_ticket', 'Each ticket needs a type (' . implode( ', ', array_keys( $counts ) ) . ') and a quantity from 1 to 50.' );
		}
		$counts[ $type ] += $qty;
	}
	$total = array_sum( $counts );
	if ( $total < 1 ) {
		return wellcon_api_error( 'no_tickets', 'At least one ticket is required.' );
	}

	// Same external_ref from the same developer = same registration, nothing is created twice.
	$refKey = 'wellcon_api_ref_' . md5( $source . '|' . $ref );
	$prior  = get_option( $refKey );
	if ( $prior ) {
		return new WP_REST_Response( [ 'status' => 'duplicate', 'external_ref' => $ref, 'user_id' => (int) $prior ], 200 );
	}

	try {
		$user = get_user_by( 'email', $email );
		if ( $user && user_can( $user, 'manage_options' ) ) {
			return wellcon_api_error( 'email_reserved', 'This email cannot be used for registration.', 409 );
		}
		if ( ! $user ) {
			$userId = wp_insert_user( [
				'user_login' => wellcon_api_unique_login( $email ),
				'user_email' => $email,
				'first_name' => $first,
				'last_name'  => $last,
				'nickname'   => $first . ' ' . $last,
				'role'       => Roles::TICKET_PURCHASER_2026,
				'user_pass'  => wp_generate_password( 24 ),
			] );
			if ( is_wp_error( $userId ) ) {
				return wellcon_api_error( 'user_failed', $userId->get_error_message(), 409 );
			}
			$user = get_user_by( 'id', $userId );
		}

		$used     = array_filter( $counts );
		$mainType = array_key_first( $used );

		$deps['purchase']->handle_ticket_purchase(
			$user->ID, $first, $user, $last, $phone, null, $mainType, count( $used ), $total,
			$counts[ TicketTypes::VIP ], $counts[ TicketTypes::EXPO ], $counts[ TicketTypes::GENERAL_ADMISSION ],
			false, $source
		);

		// 2+ tickets: same outside-system entry the GHL and Alex handlers create.
		if ( $total > 1 && ! empty( $deps['outside'] ) ) {
			$entity                        = new AddAttendeeOutsideSystemEntity();
			$entity->nameFirst             = $first;
			$entity->nameLast              = $last;
			$entity->email                 = $email;
			$entity->generalAdmissionCount = $counts[ TicketTypes::GENERAL_ADMISSION ];
			$entity->expoCount             = $counts[ TicketTypes::EXPO ];
			$entity->vipCount              = $counts[ TicketTypes::VIP ];
			$entity->source                = $source;
			$deps['outside']->add( $entity );
		}
	} catch ( Throwable $e ) {
		wellcon_api_log( 'wellcon-api failed for ' . $source . ': ' . $e->getMessage() );
		return wellcon_api_error( 'registration_failed', 'Registration could not be completed. Contact the MyWellCon team.', 500 );
	}

	add_option( $refKey, $user->ID, '', 'no' );
	update_user_meta( $user->ID, 'wellcon_api_source', $source );
	wellcon_api_log( 'wellcon-api registration', [ 'source' => $source, 'ref' => $ref, 'user' => $user->ID, 'tickets' => $counts ] );

	return new WP_REST_Response( [
		'status'       => 'created',
		'external_ref' => $ref,
		'user_id'      => $user->ID,
		'email'        => $email,
		'tickets'      => [
			'expo'              => $counts[ TicketTypes::EXPO ],
			'general_admission' => $counts[ TicketTypes::GENERAL_ADMISSION ],
			'vip'               => $counts[ TicketTypes::VIP ],
			'total'             => $total,
		],
	], 201 );
}

// WP-CLI: wp wellcon-api create <name> | list | revoke <name>
if ( defined( 'WP_CLI' ) && WP_CLI ) {
	class Wellcon_Api_CLI {
		public function create( $args ) {
			$name = $args[0];
			$keys = wellcon_api_keys();
			if ( ! preg_match( '/^[A-Za-z][A-Za-z0-9_-]{1,29}$/', $name ) ) {
				WP_CLI::error( 'Name must be 2-30 characters: letters, numbers, dash, underscore.' );
			}
			if ( isset( $keys[ $name ] ) ) {
				WP_CLI::error( 'That name already exists. Revoke it first.' );
			}
			$key           = 'wc_' . bin2hex( random_bytes( 24 ) );
			$keys[ $name ] = hash( 'sha256', $key );
			update_option( 'wellcon_api_keys', $keys, false );
			WP_CLI::success( "Key for $name (shown once, store it safely): $key" );
		}

		/** @subcommand list */
		public function list_keys() {
			foreach ( array_keys( wellcon_api_keys() ) as $name ) {
				WP_CLI::line( $name );
			}
		}

		public function revoke( $args ) {
			$keys = wellcon_api_keys();
			if ( ! isset( $keys[ $args[0] ] ) ) {
				WP_CLI::error( 'No such key.' );
			}
			unset( $keys[ $args[0] ] );
			update_option( 'wellcon_api_keys', $keys, false );
			WP_CLI::success( 'Revoked ' . $args[0] );
		}
	}
	WP_CLI::add_command( 'wellcon-api', 'Wellcon_Api_CLI' );
}
