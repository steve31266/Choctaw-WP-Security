<?php
/**
 * Searches code directories for references to a user's login or email.
 *
 * @package Choctaw_Wp_Security
 */

defined( 'ABSPATH' ) || exit;

/**
 * Greps WordPress code paths for username/email matches.
 */
class Choctaw_Wp_Security_User_File_Activity_Scanner {

	const SCAN_TIME_BUDGET = 25;
	const MATCH_CAP        = 100;
	const MAX_FILE_BYTES   = 2097152;

	/**
	 * Text-ish extensions scanned for matches.
	 *
	 * @var array<int, string>
	 */
	private static $searchable_extensions = array(
		'php',
		'phtml',
		'js',
		'css',
		'html',
		'htm',
		'txt',
		'json',
		'xml',
		'ini',
		'md',
	);

	/**
	 * Directory basenames skipped during recursive walks.
	 *
	 * @var array<int, string>
	 */
	private static $skipped_directory_basenames = array(
		'node_modules',
		'.git',
		'vendor',
		'uploads',
		'cache',
		'.svn',
		'.hg',
	);

	/**
	 * Users table discovery helper.
	 *
	 * @var Choctaw_Wp_Security_Users_Table_Discovery
	 */
	private $discovery;

	/**
	 * Constructor.
	 *
	 * @param Choctaw_Wp_Security_Users_Table_Discovery|null $discovery Optional discovery helper.
	 */
	public function __construct( $discovery = null ) {
		$this->discovery = $discovery instanceof Choctaw_Wp_Security_Users_Table_Discovery
			? $discovery
			: new Choctaw_Wp_Security_Users_Table_Discovery();
	}

	/**
	 * Search code directories for references to a user's login or email.
	 *
	 * @param string $users_table Validated users table name.
	 * @param int    $user_id     User ID.
	 * @return array<string, mixed>
	 */
	public function scan_user_file_activity( $users_table, $user_id ) {
		$users_table = $this->discovery->validate_table_name( $users_table );
		$user_id     = (int) $user_id;

		if ( false === $users_table || $user_id <= 0 ) {
			return $this->error_response(
				__( 'The requested file activity could not be loaded.', 'choctaw-wp-security' )
			);
		}

		$user = $this->fetch_user_identifiers( $users_table, $user_id );

		if ( null === $user ) {
			return $this->error_response(
				__( 'The requested user was not found in the selected users table.', 'choctaw-wp-security' )
			);
		}

		$needles = array();

		if ( '' !== $user['user_login'] ) {
			$needles[] = $user['user_login'];
		}

		if ( '' !== $user['user_email'] && $user['user_email'] !== $user['user_login'] ) {
			$needles[] = $user['user_email'];
		}

		if ( empty( $needles ) ) {
			return array(
				'success'         => true,
				'user_id'         => $user_id,
				'user_login'      => $user['user_login'],
				'user_email'      => $user['user_email'],
				'matches'         => array(),
				'capped'          => false,
				'cap'             => self::MATCH_CAP,
				'scan_incomplete' => false,
			);
		}

		$start_time      = microtime( true );
		$time_budget     = $this->get_scan_time_budget();
		$scan_incomplete = false;
		$capped          = false;
		$matches         = array();

		$this->scan_root_files( $needles, $matches, $start_time, $time_budget, $scan_incomplete, $capped );

		$directories = array(
			'wp-admin',
			'wp-includes',
			'wp-content/plugins',
			'wp-content/themes',
			'wp-content/mu-plugins',
		);

		foreach ( $directories as $directory ) {
			if ( $scan_incomplete || $capped ) {
				break;
			}

			$this->scan_directory( $directory, $needles, $matches, $start_time, $time_budget, $scan_incomplete, $capped );
		}

		return array(
			'success'         => true,
			'user_id'         => $user_id,
			'user_login'      => $user['user_login'],
			'user_email'      => $user['user_email'],
			'matches'         => $matches,
			'capped'          => $capped,
			'cap'             => self::MATCH_CAP,
			'scan_incomplete' => $scan_incomplete,
		);
	}

	/**
	 * Fetch login and email for a user ID.
	 *
	 * @param string $users_table Validated users table name.
	 * @param int    $user_id     User ID.
	 * @return array{user_login: string, user_email: string}|null
	 */
	private function fetch_user_identifiers( $users_table, $user_id ) {
		global $wpdb;

		$users_sql = $this->discovery->quote_table_name( $users_table );
		$row       = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT user_login, user_email FROM {$users_sql} WHERE ID = %d LIMIT 1",
				$user_id
			),
			ARRAY_A
		);

		if ( ! is_array( $row ) ) {
			return null;
		}

		return array(
			'user_login' => isset( $row['user_login'] ) ? (string) $row['user_login'] : '',
			'user_email' => isset( $row['user_email'] ) ? (string) $row['user_email'] : '',
		);
	}

	/**
	 * Scan files directly under the WordPress root.
	 *
	 * @param array<int, string>               $needles         Search terms.
	 * @param array<int, array<string, mixed>> $matches         Match accumulator.
	 * @param float                            $start_time      Scan start time.
	 * @param int                              $time_budget     Allowed duration in seconds.
	 * @param bool                             $scan_incomplete Incomplete flag.
	 * @param bool                             $capped          Cap flag.
	 * @return void
	 */
	private function scan_root_files( array $needles, array &$matches, $start_time, $time_budget, &$scan_incomplete, &$capped ) {
		$root = wp_normalize_path( ABSPATH );

		if ( ! is_dir( $root ) || ! is_readable( $root ) ) {
			return;
		}

		$entries = @scandir( $root );

		if ( ! is_array( $entries ) ) {
			return;
		}

		foreach ( $entries as $entry ) {
			if ( $this->scan_timed_out( $start_time, $time_budget ) ) {
				$scan_incomplete = true;
				return;
			}

			if ( $capped || '.' === $entry || '..' === $entry ) {
				continue;
			}

			$absolute = wp_normalize_path( trailingslashit( $root ) . $entry );

			if ( ! is_file( $absolute ) || ! is_readable( $absolute ) ) {
				continue;
			}

			if ( ! $this->is_searchable_file( $entry ) ) {
				continue;
			}

			$this->scan_file( $absolute, $entry, $needles, $matches, $capped );

			if ( $capped ) {
				return;
			}
		}
	}

	/**
	 * Recursively scan a directory under ABSPATH.
	 *
	 * @param string                           $relative_directory Relative directory path.
	 * @param array<int, string>               $needles            Search terms.
	 * @param array<int, array<string, mixed>> $matches            Match accumulator.
	 * @param float                            $start_time         Scan start time.
	 * @param int                              $time_budget        Allowed duration in seconds.
	 * @param bool                             $scan_incomplete    Incomplete flag.
	 * @param bool                             $capped             Cap flag.
	 * @return void
	 */
	private function scan_directory( $relative_directory, array $needles, array &$matches, $start_time, $time_budget, &$scan_incomplete, &$capped ) {
		$directory_path = wp_normalize_path( trailingslashit( ABSPATH ) . $relative_directory );

		if ( ! is_dir( $directory_path ) || ! is_readable( $directory_path ) ) {
			return;
		}

		try {
			$iterator = new RecursiveIteratorIterator(
				new RecursiveCallbackFilterIterator(
					new RecursiveDirectoryIterator(
						$directory_path,
						FilesystemIterator::SKIP_DOTS | FilesystemIterator::FOLLOW_SYMLINKS
					),
					function ( $current ) {
						if ( ! $current instanceof SplFileInfo ) {
							return false;
						}

						if ( $current->isDir() ) {
							return ! in_array( $current->getFilename(), self::$skipped_directory_basenames, true );
						}

						return $this->is_searchable_file( $current->getFilename() );
					}
				)
			);
		} catch ( Exception $exception ) {
			return;
		}

		foreach ( $iterator as $file ) {
			if ( $this->scan_timed_out( $start_time, $time_budget ) ) {
				$scan_incomplete = true;
				return;
			}

			if ( $capped || ! $file instanceof SplFileInfo || ! $file->isFile() || ! $file->isReadable() ) {
				continue;
			}

			$absolute = wp_normalize_path( $file->getPathname() );
			$relative = $this->to_relative_path( $absolute );

			if ( '' === $relative ) {
				continue;
			}

			$this->scan_file( $absolute, $relative, $needles, $matches, $capped );

			if ( $capped ) {
				return;
			}
		}
	}

	/**
	 * Scan one file for needle matches.
	 *
	 * @param string                           $absolute_path Absolute file path.
	 * @param string                           $relative_path Relative file path.
	 * @param array<int, string>               $needles       Search terms.
	 * @param array<int, array<string, mixed>> $matches       Match accumulator.
	 * @param bool                             $capped        Cap flag.
	 * @return void
	 */
	private function scan_file( $absolute_path, $relative_path, array $needles, array &$matches, &$capped ) {
		$size = @filesize( $absolute_path );

		if ( false === $size || $size > self::MAX_FILE_BYTES || $size <= 0 ) {
			return;
		}

		$handle = @fopen( $absolute_path, 'rb' );

		if ( false === $handle ) {
			return;
		}

		$line_number = 0;
		$path_parts  = $this->split_relative_path( $relative_path );

		while ( ! feof( $handle ) ) {
			$line = fgets( $handle );

			if ( false === $line ) {
				break;
			}

			++$line_number;
			$line = rtrim( $line, "\r\n" );

			foreach ( $needles as $needle ) {
				if ( false === stripos( $line, $needle ) ) {
					continue;
				}

				$matches[] = array(
					'path'        => $path_parts['path'],
					'filename'    => $path_parts['filename'],
					'line_number' => $line_number,
					'match'       => $needle,
					'contents'    => $line,
				);

				if ( count( $matches ) >= self::MATCH_CAP ) {
					$capped = true;
					fclose( $handle );
					return;
				}

				// One match row per line is enough even if both needles hit.
				break;
			}
		}

		fclose( $handle );
	}

	/**
	 * Split a relative path into directory path and filename.
	 *
	 * @param string $relative_path Relative file path.
	 * @return array{path: string, filename: string}
	 */
	private function split_relative_path( $relative_path ) {
		$relative_path = wp_normalize_path( (string) $relative_path );
		$filename      = basename( $relative_path );
		$directory     = dirname( $relative_path );

		if ( '.' === $directory || '' === $directory ) {
			return array(
				'path'     => '/',
				'filename' => $filename,
			);
		}

		return array(
			'path'     => trailingslashit( $directory ),
			'filename' => $filename,
		);
	}

	/**
	 * Convert an absolute path to an ABSPATH-relative path.
	 *
	 * @param string $absolute_path Absolute path.
	 * @return string
	 */
	private function to_relative_path( $absolute_path ) {
		$normalized = wp_normalize_path( $absolute_path );
		$root       = trailingslashit( wp_normalize_path( ABSPATH ) );

		if ( 0 !== strpos( $normalized, $root ) ) {
			return '';
		}

		return ltrim( substr( $normalized, strlen( $root ) ), '/' );
	}

	/**
	 * Determine whether a filename should be searched.
	 *
	 * @param string $filename File basename.
	 * @return bool
	 */
	private function is_searchable_file( $filename ) {
		$filename = (string) $filename;

		if ( '' === $filename ) {
			return false;
		}

		if ( in_array( $filename, array( '.htaccess', '.user.ini', 'php.ini' ), true ) ) {
			return true;
		}

		$extension = strtolower( pathinfo( $filename, PATHINFO_EXTENSION ) );

		return in_array( $extension, self::$searchable_extensions, true );
	}

	/**
	 * Resolve the scan time budget in seconds.
	 *
	 * @return int
	 */
	private function get_scan_time_budget() {
		$max_execution_time = (int) ini_get( 'max_execution_time' );

		if ( $max_execution_time <= 0 ) {
			return self::SCAN_TIME_BUDGET;
		}

		return max( 5, min( self::SCAN_TIME_BUDGET, $max_execution_time - 5 ) );
	}

	/**
	 * Determine whether the scan has exceeded its time budget.
	 *
	 * @param float $start_time  Scan start time.
	 * @param int   $time_budget Allowed duration in seconds.
	 * @return bool
	 */
	private function scan_timed_out( $start_time, $time_budget ) {
		return ( microtime( true ) - $start_time ) >= $time_budget;
	}

	/**
	 * Build an error response payload.
	 *
	 * @param string $message Error message.
	 * @return array<string, mixed>
	 */
	private function error_response( $message ) {
		return array(
			'success'         => false,
			'message'         => (string) $message,
			'matches'         => array(),
			'capped'          => false,
			'cap'             => self::MATCH_CAP,
			'scan_incomplete' => false,
		);
	}
}
