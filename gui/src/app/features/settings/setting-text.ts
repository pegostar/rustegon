/** Localized label and description of a setting (PD-231). */
export interface SettingText {
  label: string;
  doc: string;
}

let texts: Record<string, SettingText> | undefined;

/**
 * The console's own wording of each known setting, so the page reads in the user's language;
 * the server's English description stays the fallback for a setting added later. Built on first
 * use: $localize must not run at module load, before the translations are in (main.ts).
 */
export function settingText(name: string): SettingText | undefined {
  texts ??= build();
  return texts[name];
}

function build(): Record<string, SettingText> {
  const t = (label: string, doc: string): SettingText => ({ label, doc });
  return {
    'node.data_dir': t(
      $localize`:@@setting.node.data_dir:Data directory`,
      $localize`:@@setting.node.data_dir.doc:Directory of the node's data: stores, logs and backups by default.`,
    ),
    'gui.enabled': t(
      $localize`:@@setting.gui.enabled:Web console`,
      $localize`:@@setting.gui.enabled.doc:Serve this console under /ui of the REST listener.`,
    ),
    'dev.allow_inline_secrets': t(
      $localize`:@@setting.dev.allow_inline_secrets:Inline secrets`,
      $localize`:@@setting.dev.allow_inline_secrets.doc:Allow secret values written directly in the configuration (development only).`,
    ),
    'log.level': t(
      $localize`:@@setting.log.level:Log level`,
      $localize`:@@setting.log.level.doc:Log filter, for example info or info,rustegon_storage=debug.`,
    ),
    'log.dir': t(
      $localize`:@@setting.log.dir:Log directory`,
      $localize`:@@setting.log.dir.doc:Directory of the JSON log files (default: logs in the data directory).`,
    ),
    'log.max_file_size': t(
      $localize`:@@setting.log.max_file_size:Log file size`,
      $localize`:@@setting.log.max_file_size.doc:Size in bytes at which the log file is rotated.`,
    ),
    'log.max_files': t(
      $localize`:@@setting.log.max_files:Log files kept`,
      $localize`:@@setting.log.max_files.doc:Number of log files kept.`,
    ),
    'log.stderr': t(
      $localize`:@@setting.log.stderr:Log to the console`,
      $localize`:@@setting.log.stderr.doc:Also write readable logs to the standard error stream.`,
    ),
    'listen.grpc': t(
      $localize`:@@setting.listen.grpc:gRPC address`,
      $localize`:@@setting.listen.grpc.doc:Address (ip:port) of the gRPC listener for drivers; port 0 picks a free port.`,
    ),
    'listen.http': t(
      $localize`:@@setting.listen.http:REST address`,
      $localize`:@@setting.listen.http.doc:Address (ip:port) of the REST listener and of this console; port 0 picks a free port.`,
    ),
    'listen.shutdown_grace_secs': t(
      $localize`:@@setting.listen.shutdown_grace_secs:Shutdown grace period`,
      $localize`:@@setting.listen.shutdown_grace_secs.doc:Seconds a shutdown waits for the requests in progress.`,
    ),
    'listen.drain_delay_secs': t(
      $localize`:@@setting.listen.drain_delay_secs:Drain delay`,
      $localize`:@@setting.listen.drain_delay_secs.doc:Seconds a shutdown keeps serving, reported as not ready, before it stops accepting connections.`,
    ),
    'security.tls': t(
      $localize`:@@setting.security.tls:TLS`,
      $localize`:@@setting.security.tls.doc:TLS on the client listeners (single node; always on in a cluster).`,
    ),
    'security.certs_dir': t(
      $localize`:@@setting.security.certs_dir:Certificates directory`,
      $localize`:@@setting.security.certs_dir.doc:Directory of ca.crt, node.crt and node.key (default: certs in the data directory).`,
    ),
    'security.cursor_token_key_file': t(
      $localize`:@@setting.security.cursor_token_key_file:Cursor token key file`,
      $localize`:@@setting.security.cursor_token_key_file.doc:Key file that seals the continuation tokens of cursors.`,
    ),
    'security.turnkey_admin': t(
      $localize`:@@setting.security.turnkey_admin:First-start admin account`,
      $localize`:@@setting.security.turnkey_admin.doc:At the first start, create admin/admin, to be changed at the first login; loopback only.`,
    ),
    'tls.cert_file': t(
      $localize`:@@setting.tls.cert_file:Node certificate`,
      $localize`:@@setting.tls.cert_file.doc:PEM certificate chain of this node (default: node.crt in the certificates directory).`,
    ),
    'tls.key_file': t(
      $localize`:@@setting.tls.key_file:Node private key`,
      $localize`:@@setting.tls.key_file.doc:PEM private key of this node (default: node.key in the certificates directory).`,
    ),
    'tls.ca_file': t(
      $localize`:@@setting.tls.ca_file:Cluster CA`,
      $localize`:@@setting.tls.ca_file.doc:PEM certificate of the cluster CA (default: ca.crt in the certificates directory).`,
    ),
    'tls.client_ca_file': t(
      $localize`:@@setting.tls.client_ca_file:Client CA`,
      $localize`:@@setting.tls.client_ca_file.doc:CA that verifies client certificates (default: the cluster CA).`,
    ),
    'tls.client_cert': t(
      $localize`:@@setting.tls.client_cert:Client certificates`,
      $localize`:@@setting.tls.client_cert.doc:Client certificates on the client listeners: none, or optional for X.509 login.`,
    ),
    'tls.min_version': t(
      $localize`:@@setting.tls.min_version:Minimum TLS version`,
      $localize`:@@setting.tls.min_version.doc:Oldest TLS version accepted.`,
    ),
    'tls.reload_poll_secs': t(
      $localize`:@@setting.tls.reload_poll_secs:Certificate reload poll`,
      $localize`:@@setting.tls.reload_poll_secs.doc:Seconds between fallback checks for renewed certificates.`,
    ),
    'tls.watch_secs': t(
      $localize`:@@setting.tls.watch_secs:Certificate change check`,
      $localize`:@@setting.tls.watch_secs.doc:Seconds between checks for changed certificate files (0 = off).`,
    ),
    'auth.scram_iterations': t(
      $localize`:@@setting.auth.scram_iterations:Password hashing iterations`,
      $localize`:@@setting.auth.scram_iterations.doc:PBKDF2 iterations of new SCRAM-SHA-256 credentials; more is slower to attack and to log in.`,
    ),
    'auth.session_idle_timeout_gui_secs': t(
      $localize`:@@setting.auth.session_idle_timeout_gui_secs:Console idle timeout`,
      $localize`:@@setting.auth.session_idle_timeout_gui_secs.doc:Seconds of inactivity after which a console session ends.`,
    ),
    'auth.session_idle_timeout_driver_secs': t(
      $localize`:@@setting.auth.session_idle_timeout_driver_secs:Driver idle timeout`,
      $localize`:@@setting.auth.session_idle_timeout_driver_secs.doc:Seconds of inactivity after which a driver or CLI session ends.`,
    ),
    'auth.session_absolute_timeout_secs': t(
      $localize`:@@setting.auth.session_absolute_timeout_secs:Maximum session length`,
      $localize`:@@setting.auth.session_absolute_timeout_secs.doc:Seconds after which any session ends, active or not.`,
    ),
    'lockout.enabled': t(
      $localize`:@@setting.lockout.enabled:Account lockout`,
      $localize`:@@setting.lockout.enabled.doc:Lock an account after repeated failed logins.`,
    ),
    'lockout.max_failures': t(
      $localize`:@@setting.lockout.max_failures:Failed logins before lockout`,
      $localize`:@@setting.lockout.max_failures.doc:Failed logins within the window that lock the account.`,
    ),
    'lockout.window_secs': t(
      $localize`:@@setting.lockout.window_secs:Failed login window`,
      $localize`:@@setting.lockout.window_secs.doc:Seconds in which failed logins are counted.`,
    ),
    'lockout.lock_secs': t(
      $localize`:@@setting.lockout.lock_secs:Lockout duration`,
      $localize`:@@setting.lockout.lock_secs.doc:Seconds of the first lockout; it doubles at each further lockout.`,
    ),
    'lockout.max_lock_secs': t(
      $localize`:@@setting.lockout.max_lock_secs:Maximum lockout duration`,
      $localize`:@@setting.lockout.max_lock_secs.doc:Longest lockout after doubling, in seconds.`,
    ),
    'lockout.max_tracked': t(
      $localize`:@@setting.lockout.max_tracked:Users tracked for lockout`,
      $localize`:@@setting.lockout.max_tracked.doc:Maximum user names tracked in memory on each node.`,
    ),
    'rate_limit.enabled': t(
      $localize`:@@setting.rate_limit.enabled:Request limits`,
      $localize`:@@setting.rate_limit.enabled.doc:Limit the rate of logins, sessions and requests.`,
    ),
    'rate_limit.auth_per_ip_per_min': t(
      $localize`:@@setting.rate_limit.auth_per_ip_per_min:Logins per minute per IP`,
      $localize`:@@setting.rate_limit.auth_per_ip_per_min.doc:Login attempts per minute from one IP address (0 = unlimited).`,
    ),
    'rate_limit.auth_per_ip_burst': t(
      $localize`:@@setting.rate_limit.auth_per_ip_burst:Login burst per IP`,
      $localize`:@@setting.rate_limit.auth_per_ip_burst.doc:Login attempts from one IP address allowed at once.`,
    ),
    'rate_limit.auth_per_user_per_min': t(
      $localize`:@@setting.rate_limit.auth_per_user_per_min:Logins per minute per user`,
      $localize`:@@setting.rate_limit.auth_per_user_per_min.doc:Login attempts per minute for one user name (0 = unlimited).`,
    ),
    'rate_limit.auth_per_user_burst': t(
      $localize`:@@setting.rate_limit.auth_per_user_burst:Login burst per user`,
      $localize`:@@setting.rate_limit.auth_per_user_burst.doc:Login attempts for one user name allowed at once.`,
    ),
    'rate_limit.session_per_user_per_min': t(
      $localize`:@@setting.rate_limit.session_per_user_per_min:Sessions per minute per user`,
      $localize`:@@setting.rate_limit.session_per_user_per_min.doc:Sessions opened per minute by one user (0 = unlimited).`,
    ),
    'rate_limit.session_per_user_burst': t(
      $localize`:@@setting.rate_limit.session_per_user_burst:Session burst per user`,
      $localize`:@@setting.rate_limit.session_per_user_burst.doc:Sessions one user may open at once.`,
    ),
    'rate_limit.request_per_ip_per_sec': t(
      $localize`:@@setting.rate_limit.request_per_ip_per_sec:Requests per second per IP`,
      $localize`:@@setting.rate_limit.request_per_ip_per_sec.doc:Requests per second from one IP address (0 = unlimited).`,
    ),
    'rate_limit.request_per_ip_burst': t(
      $localize`:@@setting.rate_limit.request_per_ip_burst:Request burst per IP`,
      $localize`:@@setting.rate_limit.request_per_ip_burst.doc:Requests from one IP address allowed at once.`,
    ),
    'rate_limit.request_per_user_per_sec': t(
      $localize`:@@setting.rate_limit.request_per_user_per_sec:Requests per second per user`,
      $localize`:@@setting.rate_limit.request_per_user_per_sec.doc:Requests per second from one user (0 = unlimited).`,
    ),
    'rate_limit.request_per_user_burst': t(
      $localize`:@@setting.rate_limit.request_per_user_burst:Request burst per user`,
      $localize`:@@setting.rate_limit.request_per_user_burst.doc:Requests from one user allowed at once.`,
    ),
    'rate_limit.admin_per_user_per_min': t(
      $localize`:@@setting.rate_limit.admin_per_user_per_min:Admin operations per minute`,
      $localize`:@@setting.rate_limit.admin_per_user_per_min.doc:Expensive admin operations per minute by one user (0 = unlimited).`,
    ),
    'rate_limit.admin_per_user_burst': t(
      $localize`:@@setting.rate_limit.admin_per_user_burst:Admin operation burst`,
      $localize`:@@setting.rate_limit.admin_per_user_burst.doc:Expensive admin operations one user may start at once.`,
    ),
    'rate_limit.max_buckets': t(
      $localize`:@@setting.rate_limit.max_buckets:Tracked clients`,
      $localize`:@@setting.rate_limit.max_buckets.doc:Maximum IP addresses and users tracked in memory on each node.`,
    ),
    'audit.enabled': t(
      $localize`:@@setting.audit.enabled:Audit log`,
      $localize`:@@setting.audit.enabled.doc:Write the security audit log.`,
    ),
    'audit.sink': t(
      $localize`:@@setting.audit.sink:Audit destination`,
      $localize`:@@setting.audit.sink.doc:Where audit events are written (file).`,
    ),
    'audit.dir': t(
      $localize`:@@setting.audit.dir:Audit directory`,
      $localize`:@@setting.audit.dir.doc:Directory of the audit files (default: audit in the data directory).`,
    ),
    'audit.max_file_size': t(
      $localize`:@@setting.audit.max_file_size:Audit file size`,
      $localize`:@@setting.audit.max_file_size.doc:Size in bytes at which a new audit file is started.`,
    ),
    'audit.max_files': t(
      $localize`:@@setting.audit.max_files:Audit files kept`,
      $localize`:@@setting.audit.max_files.doc:Number of audit files kept; 0 keeps all.`,
    ),
    'audit.data_writes': t(
      $localize`:@@setting.audit.data_writes:Audit data changes`,
      $localize`:@@setting.audit.data_writes.doc:Also audit the data changes made from this console.`,
    ),
    'storage.block_size': t(
      $localize`:@@setting.storage.block_size:Block size`,
      $localize`:@@setting.storage.block_size.doc:Target size in bytes of an uncompressed data block on disk.`,
    ),
    'storage.bottommost_zstd_level': t(
      $localize`:@@setting.storage.bottommost_zstd_level:Compression level`,
      $localize`:@@setting.storage.bottommost_zstd_level.doc:Zstd level (1 to 19) of the oldest, largest data files; higher is smaller and slower.`,
    ),
    'storage.block_cache_size': t(
      $localize`:@@setting.storage.block_cache_size:Block cache size`,
      $localize`:@@setting.storage.block_cache_size.doc:Memory in bytes for cached data blocks (0 disables the cache).`,
    ),
    'storage.memtable_size': t(
      $localize`:@@setting.storage.memtable_size:Write buffer size`,
      $localize`:@@setting.storage.memtable_size.doc:Bytes of recent writes kept in memory before they are flushed to disk.`,
    ),
    'storage.encryption': t(
      $localize`:@@setting.storage.encryption:Encryption at rest`,
      $localize`:@@setting.storage.encryption.doc:Encryption of the data files: none or aes-256-gcm.`,
    ),
    'storage.encryption_key_file': t(
      $localize`:@@setting.storage.encryption_key_file:Encryption key file`,
      $localize`:@@setting.storage.encryption_key_file.doc:File of the 32-byte key that protects the data keys, when the key comes from a file.`,
    ),
    'storage.encryption_key_provider': t(
      $localize`:@@setting.storage.encryption_key_provider:Encryption key source`,
      $localize`:@@setting.storage.encryption_key_provider.doc:Where the encryption key comes from: a file or an environment variable.`,
    ),
    'storage.encryption_key_env': t(
      $localize`:@@setting.storage.encryption_key_env:Encryption key variable`,
      $localize`:@@setting.storage.encryption_key_env.doc:Environment variable holding the encryption key in base64, when the key comes from the environment.`,
    ),
    'raft.log_segment_size': t(
      $localize`:@@setting.raft.log_segment_size:Replication log segment size`,
      $localize`:@@setting.raft.log_segment_size.doc:Size in bytes at which the replication log starts a new file.`,
    ),
    'backup.allowed_destinations': t(
      $localize`:@@setting.backup.allowed_destinations:Allowed backup destinations`,
      $localize`:@@setting.backup.allowed_destinations.doc:Directories, file:// or s3:// URLs the server may back up to, besides the backups directory; empty allows only that one.`,
    ),
    'backup.pitr': t(
      $localize`:@@setting.backup.pitr:Point-in-time recovery`,
      $localize`:@@setting.backup.pitr.doc:Archiving of the change log for point-in-time recovery; set in the configuration file.`,
    ),
    'backup.s3': t(
      $localize`:@@setting.backup.s3:S3 destinations`,
      $localize`:@@setting.backup.s3.doc:Credentials and options of S3-compatible destinations; set in the configuration file.`,
    ),
  };
}
