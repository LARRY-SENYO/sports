/**
 * =============================================================================
 * TITAN SPORTS OS - COMPLETE ARCHITECTURE CONTROLLER (LIGHT EDITION)
 * =============================================================================
 * Features:
 * 1. Gateway Screen (Sign In & Sign Up appears BEFORE system access)
 * 2. Dedicated Administrator Page & Dedicated User / Athlete Portal
 * 3. Two-Factor Authentication (2FA) with RFC 6238 TOTP Simulator
 * 4. Cryptographic Salt & Pepper Lab (WebCrypto + Pure JS Fallback)
 * 5. Role-Based Access Control (RBAC) Matrix
 * 6. Sports Entity CRUD (Teams, Athletes, Matches, Tournaments)
 * 7. Data-Preserving Config Restore Points (Changes config, preserves data)
 * 8. Admin Audit Trails with Mandatory User Deletion Auditing
 * =============================================================================
 */

(function () {
  'use strict';

  /* ===========================================================================
     SECTION 1: GLOBAL CONSTANTS & CONFIGURATION
     Defines application storage keys, environment pepper secret, and roles.
     =========================================================================== */

  /**
   * Application-wide Pepper Secret.
   * IN PRODUCTION: Kept strictly in server environment variables or HSM.
   */
  const SYSTEM_PEPPER_SECRET = "TITAN_ENV_SECRET_PEPPER_KEY_994821";

  /**
   * LocalStorage persistence keys.
   */
  const STORAGE_KEYS = {
    USERS: 'titan_sports_users_v2',
    ENTITIES: 'titan_sports_entities_v2',
    CONFIG: 'titan_sports_config_v2',
    RESTORE_POINTS: 'titan_sports_restore_points_v2',
    AUDIT_LOGS: 'titan_sports_audit_logs_v2',
    CURRENT_USER: 'titan_sports_current_user_v2',
    IS_AUTH: 'titan_sports_is_auth_v2',
    SYSTEM_SLOT_BACKUP: 'titan_sports_slot_backup_v2'
  };

  /**
   * Role definitions with specific permission sets.
   */
  const ROLES = {
    ADMIN: {
      name: 'Super Admin',
      id: 'Admin',
      badgeClass: 'role-admin',
      permissions: [
        'manage_entities',
        'manage_matches',
        'score_matches',
        'manage_users',
        'delete_users',
        'manage_config',
        'manage_backup',
        'view_audit',
        'export_audit',
        'super_admin_only'
      ]
    },
    COACH: {
      name: 'Coach',
      id: 'Coach',
      badgeClass: 'role-coach',
      permissions: [
        'manage_entities',
        'view_matches'
      ]
    },
    REFEREE: {
      name: 'Referee',
      id: 'Referee',
      badgeClass: 'role-referee',
      permissions: [
        'score_matches',
        'view_matches'
      ]
    },
    ATHLETE: {
      name: 'Athlete',
      id: 'Athlete',
      badgeClass: 'role-athlete',
      permissions: [
        'view_own_stats',
        'view_matches'
      ]
    },
    VIEWER: {
      name: 'Viewer',
      id: 'Viewer',
      badgeClass: 'role-viewer',
      permissions: [
        'view_public'
      ]
    }
  };

  /* ===========================================================================
     SECTION 2: CRYPTOGRAPHIC ENGINE
     Handles Web Crypto SHA-256 with robust pure-JS fallback,
     per-user salt generation, and RFC 6238 Time-based One-Time Passwords (TOTP).
     =========================================================================== */

  const CryptoEngine = {
    /**
     * Generates a cryptographically secure random 32-character Hex Salt.
     * @returns {string} 32-character hex string
     */
    generateSalt() {
      if (window.crypto && window.crypto.getRandomValues) {
        const buffer = new Uint8Array(16);
        window.crypto.getRandomValues(buffer);
        return Array.from(buffer).map(b => b.toString(16).padStart(2, '0')).join('');
      }
      // Fallback
      let salt = '';
      const hexChars = '0123456789abcdef';
      for (let i = 0; i < 32; i++) {
        salt += hexChars[Math.floor(Math.random() * 16)];
      }
      return salt;
    },

    /**
     * Pure JavaScript SHA-256 fallback algorithm to guarantee 100% operation
     * across all browser contexts (file://, local dev, or secure origins).
     */
    pureJsSha256(ascii) {
      function rightRotate(value, amount) {
        return (value >>> amount) | (value << (32 - amount));
      }
      const mathPow = Math.pow;
      const maxWord = mathPow(2, 32);
      const lengthProperty = 'length';
      let i, j;
      let result = '';
      const words = [];
      const asciiBitLength = ascii[lengthProperty] * 8;
      const hash = CryptoEngine._h = CryptoEngine._h || [];
      const k = CryptoEngine._k = CryptoEngine._k || [];
      let primeCounter = k[lengthProperty];
      const isComposite = {};

      for (let candidate = 2; primeCounter < 64; candidate++) {
        if (!isComposite[candidate]) {
          for (i = 0; i < 313; i += candidate) {
            isComposite[i] = candidate;
          }
          hash[primeCounter] = (mathPow(candidate, 0.5) * maxWord) | 0;
          k[primeCounter++] = (mathPow(candidate, 1 / 3) * maxWord) | 0;
        }
      }

      ascii += '\x80';
      while (ascii[lengthProperty] % 64 - 56) ascii += '\x00';
      for (i = 0; i < ascii[lengthProperty]; i++) {
        j = ascii.charCodeAt(i);
        words[i >> 2] |= j << ((3 - i) % 4) * 8;
      }
      words[words[lengthProperty]] = (asciiBitLength / maxWord) | 0;
      words[words[lengthProperty]] = asciiBitLength;

      for (j = 0; j < words[lengthProperty]; ) {
        const w = words.slice(j, (j += 16));
        const oldHash = hash.slice(0);
        for (i = 0; i < 64; i++) {
          const w15 = w[i - 15], w2 = w[i - 2];
          const a = hash[0], e = hash[4];
          const temp1 =
            hash[7] +
            (rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25)) +
            ((e & hash[5]) ^ (~e & hash[6])) +
            k[i] +
            (w[i] =
              i < 16
                ? w[i]
                : (w[i - 16] +
                    (rightRotate(w15, 7) ^ rightRotate(w15, 18) ^ (w15 >>> 3)) +
                    w[i - 7] +
                    (rightRotate(w2, 17) ^ rightRotate(w2, 19) ^ (w2 >>> 10))) |
                  0);
          const temp2 =
            (rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22)) +
            ((a & hash[1]) ^ (a & hash[2]) ^ (hash[1] & hash[2]));

          hash[7] = hash[6];
          hash[6] = hash[5];
          hash[5] = hash[4];
          hash[4] = (hash[3] + temp1) | 0;
          hash[3] = hash[2];
          hash[2] = hash[1];
          hash[1] = hash[0];
          hash[0] = (temp1 + temp2) | 0;
        }
        for (i = 0; i < 8; i++) {
          hash[i] = (hash[i] + oldHash[i]) | 0;
        }
      }

      for (i = 0; i < 8; i++) {
        for (let i2 = 3; i2 >= 0; i2--) {
          const b = (hash[i] >> (8 * i2)) & 255;
          result += (b < 16 ? '0' : '') + b.toString(16);
        }
      }
      return result;
    },

    /**
     * Computes SHA-256 with WebCrypto API or fallback.
     */
    async sha256(message) {
      if (window.crypto && window.crypto.subtle && window.crypto.subtle.digest) {
        try {
          const msgBuffer = new TextEncoder().encode(message);
          const hashBuffer = await window.crypto.subtle.digest('SHA-256', msgBuffer);
          const hashArray = Array.from(new Uint8Array(hashBuffer));
          return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        } catch (e) {
          // fall through to pure JS
        }
      }
      return this.pureJsSha256(message);
    },

    /**
     * Compound password hashing formula:
     * Stored_Hash = SHA256( Salt + Password + Pepper )
     */
    async hashPassword(password, salt, pepper = SYSTEM_PEPPER_SECRET) {
      const compoundString = `${salt}${password}${pepper}`;
      return await this.sha256(compoundString);
    },

    /**
     * Pure JavaScript SHA-1 implementation for standards-compliant RFC 6238 TOTP.
     */
    sha1(message) {
      function rotl(n, s) { return (n << s) | (n >>> (32 - s)); }
      let msg = message;
      let len = msg.length;
      let words = [];
      for (let i = 0; i < len; i++) {
        words[i >> 2] |= (msg.charCodeAt(i) & 255) << (24 - (i % 4) * 8);
      }
      words[len >> 2] |= 0x80 << (24 - (len % 4) * 8);
      words[(((len + 8) >> 6) << 4) + 15] = len * 8;

      let H0 = 0x67452301, H1 = 0xefcdab89, H2 = 0x98badcfe, H3 = 0x10325476, H4 = 0xc3d2e1f0;
      let W = new Array(80);

      for (let i = 0; i < words.length; i += 16) {
        for (let t = 0; t < 16; t++) W[t] = words[i + t] | 0;
        for (let t = 16; t < 80; t++) W[t] = rotl(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16], 1);

        let A = H0, B = H1, C = H2, D = H3, E = H4;
        for (let t = 0; t < 80; t++) {
          let f, k;
          if (t < 20) { f = (B & C) | ((~B) & D); k = 0x5a827999; }
          else if (t < 40) { f = B ^ C ^ D; k = 0x6ed9eba1; }
          else if (t < 60) { f = (B & C) | (B & D) | (C & D); k = 0x8f1bbcdc; }
          else { f = B ^ C ^ D; k = 0xca62c1d6; }
          let temp = (rotl(A, 5) + f + E + k + W[t]) | 0;
          E = D; D = C; C = rotl(B, 30); B = A; A = temp;
        }
        H0 = (H0 + A) | 0; H1 = (H1 + B) | 0; H2 = (H2 + C) | 0; H3 = (H3 + D) | 0; H4 = (H4 + E) | 0;
      }
      return [H0, H1, H2, H3, H4];
    },

    /**
     * Pure JavaScript HMAC-SHA-1 computation for standard RFC 6238 TOTP.
     */
    hmacSha1(keyBytes, msgBytes) {
      let key = Array.from(keyBytes);
      if (key.length > 64) {
        let kStr = key.map(b => String.fromCharCode(b)).join('');
        let h = this.sha1(kStr);
        key = [];
        for (let i = 0; i < 5; i++) {
          for (let j = 3; j >= 0; j--) key.push((h[i] >> (j * 8)) & 255);
        }
      }
      while (key.length < 64) key.push(0);

      let o_key_pad = key.map(b => b ^ 0x5c);
      let i_key_pad = key.map(b => b ^ 0x36);

      let innerMsg = i_key_pad.map(b => String.fromCharCode(b)).join('') +
                     Array.from(msgBytes).map(b => String.fromCharCode(b)).join('');
      let innerHash = this.sha1(innerMsg);
      let innerBytes = [];
      for (let i = 0; i < 5; i++) {
        for (let j = 3; j >= 0; j--) innerBytes.push((innerHash[i] >> (j * 8)) & 255);
      }

      let outerMsg = o_key_pad.map(b => String.fromCharCode(b)).join('') +
                     innerBytes.map(b => String.fromCharCode(b)).join('');
      let outerHash = this.sha1(outerMsg);
      let outerBytes = [];
      for (let i = 0; i < 5; i++) {
        for (let j = 3; j >= 0; j--) outerBytes.push((outerHash[i] >> (j * 8)) & 255);
      }
      return outerBytes;
    },

    /**
     * Decodes Base32 string (RFC 4648) into Uint8Array.
     */
    base32ToBytes(base32) {
      const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
      let cleaned = (base32 || '').replace(/=+$/, '').toUpperCase();
      let bits = '';
      for (let i = 0; i < cleaned.length; i++) {
        let val = alphabet.indexOf(cleaned[i]);
        if (val === -1) continue;
        bits += val.toString(2).padStart(5, '0');
      }
      let bytes = [];
      for (let i = 0; i + 8 <= bits.length; i += 8) {
        bytes.push(parseInt(bits.substr(i, 8), 2));
      }
      return new Uint8Array(bytes);
    },

    /**
     * Standards-compliant RFC 6238 TOTP computation:
     * Synchronized with Google Authenticator, Microsoft Authenticator,
     * Apple Passwords, Authy, and the Titan Mobile Web Companion.
     * @param {string} secretSeed - Base32 encoded secret seed (e.g., JBSWY3DPEHPK3PXP)
     * @returns {Promise<string>} 6-digit rotating verification code
     */
    async generateCurrentTOTP(secretSeed = "JBSWY3DPEHPK3PXP") {
      let epoch = Math.floor(Date.now() / 1000 / 30);
      let timeBytes = new Uint8Array(8);
      for (let i = 7; i >= 0; i--) {
        timeBytes[i] = epoch & 0xff;
        epoch = Math.floor(epoch / 256);
      }
      let keyBytes = this.base32ToBytes(secretSeed);
      let hmac = this.hmacSha1(keyBytes, timeBytes);
      let offset = hmac[hmac.length - 1] & 0x0f;
      let binary = ((hmac[offset] & 0x7f) << 24) |
                   ((hmac[offset + 1] & 0xff) << 16) |
                   ((hmac[offset + 2] & 0xff) << 8) |
                   (hmac[offset + 3] & 0xff);
      let otp = binary % 1000000;
      return otp.toString().padStart(6, '0');
    },

    /**
     * Returns seconds remaining in current 30-second window.
     */
    getTOTPSecondsRemaining() {
      const epochSeconds = Math.floor(Date.now() / 1000);
      return 30 - (epochSeconds % 30);
    }
  };

  /* ===========================================================================
     SECTION 3: SEED DATA
     Pre-populates Users, Sports Entities, and Config Restore Points.
     =========================================================================== */

  const DefaultData = {
    config: {
      systemTitle: "Titan Sports OS",
      theme: "theme-light",
      sessionTimeoutMins: 30,
      strict2FA: true,
      maintenanceMode: false,
      verboseAudit: true,
      configVersion: "v2.4-LightProduction"
    },

    getInitialUsers() {
      return [
        {
          id: "USR-2026-001",
          username: "admin",
          fullname: "Super Administrator",
          email: "admin@titansports.org",
          role: "Admin",
          salt: "e8f1b34c92a74df8b50619283746a5b2",
          passwordHash: "1e1c7f0db460787e9c5aa811aeb2aa0f40d7c71baeb592750a976137684075f9",
          totpSecret: "JBSWY3DPEHPK3PXP",
          twoFactorEnabled: true,
          status: "Active",
          createdAt: "2026-01-10T08:00:00Z"
        },
        {
          id: "USR-2026-002",
          username: "coach_marcus",
          fullname: "Marcus Vance",
          email: "m.vance@titansports.org",
          role: "Coach",
          salt: "7a94c1e285f03d6b12345678abcdef01",
          passwordHash: "7553f1963283259cefdc25a1e8a9f24ba22203d9202ea6ad4169cce73167b57b",
          totpSecret: "KZXW6YTBOJUW4ZZ2",
          twoFactorEnabled: true,
          status: "Active",
          createdAt: "2026-02-14T09:30:00Z"
        },
        {
          id: "USR-2026-003",
          username: "referee_dave",
          fullname: "David Sterling",
          email: "d.sterling@referee-union.org",
          role: "Referee",
          salt: "b1c2d3e4f5061728394a5b6c7d8e9f00",
          passwordHash: "9a756cd79fa01f561917fbf78ee2bfa816995ce5e6ce54ea22c360c23945cfd3",
          totpSecret: "MFRGGZDFMY2WMZZX",
          twoFactorEnabled: true,
          status: "Active",
          createdAt: "2026-03-01T11:15:00Z"
        },
        {
          id: "USR-2026-004",
          username: "player_alex",
          fullname: "Alex Rivera",
          email: "a.rivera@titansports.org",
          role: "Athlete",
          salt: "4f5e6d7c8b9a0123456789abcdef0123",
          passwordHash: "3f3cb7bc8c2323a7bbec45279268f76d49ca9d393fb7ee23c4a45371607567cb",
          totpSecret: "NBSWY3DPEHPK3P99",
          twoFactorEnabled: true,
          status: "Active",
          createdAt: "2026-03-12T14:00:00Z"
        },
        {
          id: "USR-2026-005",
          username: "viewer_sarah",
          fullname: "Sarah Jenkins",
          email: "s.jenkins@sportsfan.net",
          role: "Viewer",
          salt: "99887766554433221100aabbccddeeff",
          passwordHash: "05cbfa119859f7d6a524a1334c4f3ce37fa7454f76274431f0cf8e96bfad2fef",
          totpSecret: "OBRWY3DPEHPK3P01",
          twoFactorEnabled: false,
          status: "Active",
          createdAt: "2026-04-05T16:20:00Z"
        }
      ];
    },

    entities: {
      teams: [
        {
          id: "TM-001",
          name: "Apex Cyber Hawks",
          sport: "Soccer",
          venue: "Titan National Arena",
          coach: "Marcus Vance",
          established: 2021,
          wins: 14,
          losses: 2,
          emblem: "🦅"
        },
        {
          id: "TM-002",
          name: "Valkyrie United",
          sport: "Soccer",
          venue: "Metro Stadium",
          coach: "Elena Rostova",
          established: 2019,
          wins: 11,
          losses: 5,
          emblem: "⚔️"
        },
        {
          id: "TM-003",
          name: "Thunderbolt BC",
          sport: "Basketball",
          venue: "Apex Court Center",
          coach: "Derrick Cole",
          established: 2018,
          wins: 22,
          losses: 6,
          emblem: "⚡"
        },
        {
          id: "TM-004",
          name: "Ironclad RFC",
          sport: "Rugby",
          venue: "Highland Park Ground",
          coach: "Liam Gallagher",
          established: 2017,
          wins: 9,
          losses: 4,
          emblem: "🛡️"
        }
      ],
      athletes: [
        {
          id: "ATH-001",
          name: "Alex Rivera",
          team: "Apex Cyber Hawks",
          sport: "Soccer",
          jerseyNumber: 10,
          position: "Striker / Forward",
          healthStatus: "Eligible",
          rating: 94
        },
        {
          id: "ATH-002",
          name: "Mateo Silva",
          team: "Apex Cyber Hawks",
          sport: "Soccer",
          jerseyNumber: 1,
          position: "Goalkeeper",
          healthStatus: "Eligible",
          rating: 89
        },
        {
          id: "ATH-003",
          name: "Jordan Sterling",
          team: "Thunderbolt BC",
          sport: "Basketball",
          jerseyNumber: 23,
          position: "Point Guard",
          healthStatus: "Eligible",
          rating: 96
        },
        {
          id: "ATH-004",
          name: "Marcus Thorne",
          team: "Ironclad RFC",
          sport: "Rugby",
          jerseyNumber: 8,
          position: "Flanker",
          healthStatus: "Recovering",
          rating: 88
        }
      ],
      matches: [
        {
          id: "MT-101",
          homeTeam: "Apex Cyber Hawks",
          awayTeam: "Valkyrie United",
          sport: "Soccer",
          dateTime: "2026-10-25 19:30",
          venue: "Titan National Arena",
          homeScore: 3,
          awayScore: 1,
          status: "Completed",
          referee: "David Sterling"
        },
        {
          id: "MT-102",
          homeTeam: "Thunderbolt BC",
          awayTeam: "Solar Flares",
          sport: "Basketball",
          dateTime: "2026-10-28 20:00",
          venue: "Apex Court Center",
          homeScore: 0,
          awayScore: 0,
          status: "Upcoming",
          referee: "David Sterling"
        },
        {
          id: "MT-103",
          homeTeam: "Ironclad RFC",
          awayTeam: "Colossus Rugby Club",
          sport: "Rugby",
          dateTime: "2026-11-02 15:00",
          venue: "Highland Park Ground",
          homeScore: 24,
          awayScore: 21,
          status: "Completed",
          referee: "Official League Panel"
        }
      ],
      tournaments: [
        {
          id: "TRN-01",
          name: "Titan Championship Cup 2026",
          sport: "Soccer",
          season: "2026-Q4",
          teamsCount: 16,
          prize: "$250,000 & Golden Shield",
          status: "In Progress"
        },
        {
          id: "TRN-02",
          name: "Premier Metro Invitational",
          sport: "Basketball",
          season: "2026-Winter",
          teamsCount: 12,
          prize: "$100,000 Trophy",
          status: "Upcoming"
        }
      ]
    },

    restorePoints: [
      {
        id: "CRP-001",
        name: "Standard Light Production",
        description: "Standard production configuration with clean light theme and strict 2FA enforcement.",
        createdAt: "2026-10-01 10:00",
        config: {
          systemTitle: "Titan Sports OS",
          theme: "theme-light",
          sessionTimeoutMins: 30,
          strict2FA: true,
          maintenanceMode: false,
          verboseAudit: true,
          configVersion: "v2.4-LightProduction"
        }
      },
      {
        id: "CRP-002",
        name: "Tournament High-Alert Mode",
        description: "15-minute aggressive session timeouts, strict 2FA, and verbose logging.",
        createdAt: "2026-10-10 14:30",
        config: {
          systemTitle: "Titan Sports OS - Tournament Finals",
          theme: "theme-light",
          sessionTimeoutMins: 15,
          strict2FA: true,
          maintenanceMode: false,
          verboseAudit: true,
          configVersion: "v2.5-TournamentFinals"
        }
      },
      {
        id: "CRP-003",
        name: "Scheduled Maintenance Mode",
        description: "Platform maintenance mode activated, restricting non-admin access.",
        createdAt: "2026-10-15 02:00",
        config: {
          systemTitle: "Titan Sports OS [Maintenance Window]",
          theme: "theme-light",
          sessionTimeoutMins: 60,
          strict2FA: true,
          maintenanceMode: true,
          verboseAudit: true,
          configVersion: "v2.3-Maintenance"
        }
      }
    ]
  };

  /* ===========================================================================
     SECTION 4: STATE MANAGEMENT & PERSISTENCE
     =========================================================================== */

  const State = {
    users: [],
    entities: {},
    config: {},
    restorePoints: [],
    auditLogs: [],
    currentUser: null,
    pending2FAUser: null,
    isAuthenticated: false, // Controls gate screen visibility

    init() {
      const storedUsers = localStorage.getItem(STORAGE_KEYS.USERS);
      this.users = storedUsers ? JSON.parse(storedUsers) : DefaultData.getInitialUsers();

      const storedEntities = localStorage.getItem(STORAGE_KEYS.ENTITIES);
      this.entities = storedEntities ? JSON.parse(storedEntities) : DefaultData.entities;

      const storedConfig = localStorage.getItem(STORAGE_KEYS.CONFIG);
      this.config = storedConfig ? JSON.parse(storedConfig) : DefaultData.config;

      const storedRP = localStorage.getItem(STORAGE_KEYS.RESTORE_POINTS);
      this.restorePoints = storedRP ? JSON.parse(storedRP) : DefaultData.restorePoints;

      const storedLogs = localStorage.getItem(STORAGE_KEYS.AUDIT_LOGS);
      this.auditLogs = storedLogs ? JSON.parse(storedLogs) : [];

      // Check auth flag
      this.isAuthenticated = localStorage.getItem(STORAGE_KEYS.IS_AUTH) === 'true';

      const storedActiveUser = localStorage.getItem(STORAGE_KEYS.CURRENT_USER);
      if (storedActiveUser) {
        const found = this.users.find(u => u.id === storedActiveUser);
        this.currentUser = found || this.users[0];
      } else {
        this.currentUser = this.users[0];
      }

      this.persistAll();
    },

    saveUsers() {
      localStorage.setItem(STORAGE_KEYS.USERS, JSON.stringify(this.users));
    },

    saveEntities() {
      localStorage.setItem(STORAGE_KEYS.ENTITIES, JSON.stringify(this.entities));
    },

    saveConfig() {
      localStorage.setItem(STORAGE_KEYS.CONFIG, JSON.stringify(this.config));
    },

    saveRestorePoints() {
      localStorage.setItem(STORAGE_KEYS.RESTORE_POINTS, JSON.stringify(this.restorePoints));
    },

    saveAuditLogs() {
      localStorage.setItem(STORAGE_KEYS.AUDIT_LOGS, JSON.stringify(this.auditLogs));
    },

    saveAuth() {
      localStorage.setItem(STORAGE_KEYS.IS_AUTH, this.isAuthenticated ? 'true' : 'false');
      if (this.currentUser) {
        localStorage.setItem(STORAGE_KEYS.CURRENT_USER, this.currentUser.id);
      }
    },

    persistAll() {
      this.saveUsers();
      this.saveEntities();
      this.saveConfig();
      this.saveRestorePoints();
      this.saveAuditLogs();
      this.saveAuth();
    }
  };

  /* ===========================================================================
     SECTION 5: AUDIT LOGGING ENGINE & MANDATORY DELETION LOGGING
     =========================================================================== */

  const AuditLogger = {
    log({ action, target, details, severity = 'INFO', targetId = '' }) {
      const actor = State.currentUser || { username: 'GATE_USER', role: 'System' };
      const newLog = {
        id: `LOG-${Date.now()}-${Math.floor(Math.random() * 1000).toString().padStart(3, '0')}`,
        timestamp: new Date().toISOString(),
        actorUsername: actor.username,
        actorRole: actor.role,
        action,
        severity,
        target,
        targetId,
        details,
        clientIp: '192.168.1.104'
      };

      State.auditLogs.unshift(newLog);
      State.saveAuditLogs();

      const badge = document.getElementById('audit-badge-counter');
      if (badge) badge.textContent = State.auditLogs.length;

      UIRenderer.renderAuditLogs();
    },

    /**
     * CRITICAL REQUIREMENT: Explicit handler for User Deletion.
     */
    logUserDeletion(deletedUser, reason) {
      this.log({
        action: 'USER_DELETED',
        severity: 'CRITICAL',
        target: `User Identity: ${deletedUser.username} (${deletedUser.fullname})`,
        targetId: deletedUser.id,
        details: `CRITICAL ACTION: User account permanently deleted by [${State.currentUser.username} (${State.currentUser.role})]. Role was [${deletedUser.role}], Salt Nonce was [${deletedUser.salt}]. Reason: "${reason}".`
      });
    }
  };

  /* ===========================================================================
     SECTION 6: RBAC & PERMISSIONS GUARD
     =========================================================================== */

  const RBACGuard = {
    hasPermission(permissionName) {
      if (!State.currentUser) return false;
      const roleDef = Object.values(ROLES).find(r => r.id === State.currentUser.role);
      if (!roleDef) return false;
      return roleDef.permissions.includes(permissionName);
    },

    applyUIPermissions() {
      const permissionElements = document.querySelectorAll('[data-permission]');
      permissionElements.forEach(el => {
        const requiredPerm = el.getAttribute('data-permission');
        const allowed = this.hasPermission(requiredPerm);

        if (!allowed) {
          el.classList.add('btn-disabled');
          el.setAttribute('disabled', 'true');
          el.title = `Access Restricted: Requires higher privileges than [${State.currentUser?.role || 'Guest'}]`;
        } else {
          el.classList.remove('btn-disabled');
          el.removeAttribute('disabled');
          el.removeAttribute('title');
        }
      });

      // Role badge in dashboard
      const dashBadge = document.getElementById('dash-active-role-badge');
      if (dashBadge && State.currentUser) {
        dashBadge.textContent = `Your Active Role: ${State.currentUser.role}`;
      }

      // Show/Hide Dedicated Administrator tab in main nav
      const adminNavTab = document.getElementById('nav-btn-admin');
      if (adminNavTab) {
        if (State.currentUser && State.currentUser.role === 'Admin') {
          adminNavTab.style.display = 'inline-flex';
        } else {
          adminNavTab.style.display = 'none';
        }
      }
    }
  };

  /* ===========================================================================
     SECTION 6B: QR CODE MANAGER & NETWORK RELAY DETECTOR
     Handles rendering standard QR codes for physical mobile device scanning,
     detecting active LAN IP address, and formatting RFC 6238 and Web TOTP URIs.
     =========================================================================== */

  const QRCodeManager = {
    networkInfo: {
      lanIp: window.location.hostname || '172.21.18.46',
      port: window.location.port || '8080',
      mobileUrl: `http://${window.location.hostname || '172.21.18.46'}:${window.location.port || '8080'}/mobile-auth.html`
    },

    gateQrMode: 'web',   // 'web' or 'app'
    modalQrMode: 'web',  // 'web' or 'app'
    viewQrMode: 'web',   // 'web' or 'app'

    async init() {
      try {
        const res = await fetch('/api/network-info');
        if (res.ok) {
          const data = await res.json();
          if (data && data.lanIp) {
            this.networkInfo.lanIp = data.lanIp;
            this.networkInfo.port = data.port || '8080';
            this.networkInfo.mobileUrl = data.mobileUrl;

            const lanEl = document.getElementById('gate-lan-url-display');
            if (lanEl) lanEl.textContent = data.mobileUrl;
          }
        }
      } catch (e) {
        // Fallback to current host
      }
      this.updateGateQRCode();
    },

    getMobileWebUrl(user) {
      const u = typeof user === 'string' ? user : (user?.username || 'admin');
      const name = typeof user === 'object' ? (user.fullname || u) : u;
      const secret = typeof user === 'object' ? (user.totpSecret || 'JBSWY3DPEHPK3PXP') : 'JBSWY3DPEHPK3PXP';
      return `http://${this.networkInfo.lanIp}:${this.networkInfo.port}/mobile-auth.html?user=${encodeURIComponent(u)}&name=${encodeURIComponent(name)}&secret=${encodeURIComponent(secret)}`;
    },

    getOtpauthUri(user) {
      const u = typeof user === 'string' ? user : (user?.username || 'admin');
      const secret = typeof user === 'object' ? (user.totpSecret || 'JBSWY3DPEHPK3PXP') : 'JBSWY3DPEHPK3PXP';
      return `otpauth://totp/TitanSports:${encodeURIComponent(u)}?secret=${encodeURIComponent(secret)}&issuer=TitanSports&algorithm=SHA1&digits=6&period=30`;
    },

    renderQRCode(targetElId, content, size = 160) {
      const container = document.getElementById(targetElId);
      if (!container) return;
      container.innerHTML = '';

      if (typeof QRCode !== 'undefined') {
        new QRCode(container, {
          text: content,
          width: size,
          height: size,
          colorDark: "#0f172a",
          colorLight: "#ffffff",
          correctLevel: QRCode.CorrectLevel.M
        });
      } else {
        container.innerHTML = `<div class="p-2 text-xs text-muted text-center">QR Library loading...<br><code>${content.substring(0, 30)}...</code></div>`;
      }
    },

    updateGateQRCode(user) {
      const targetUser = user || State.pending2FAUser || State.currentUser || State.users[0];
      const content = this.gateQrMode === 'web' 
        ? this.getMobileWebUrl(targetUser) 
        : this.getOtpauthUri(targetUser);
      
      this.renderQRCode('gate-companion-qrcode', content, 150);

      const linkEl = document.getElementById('gate-qr-direct-link');
      if (linkEl) linkEl.href = this.getMobileWebUrl(targetUser);

      const statusEl = document.getElementById('gate-qr-status-label');
      if (statusEl) {
        statusEl.textContent = this.gateQrMode === 'web' 
          ? `Ready for phone camera (@${targetUser.username})` 
          : `Ready for Google/Apple app (@${targetUser.username})`;
      }
    }
  };

  /* ===========================================================================
     SECTION 7: AUTHENTICATION & 2FA CONTROLLER
     =========================================================================== */

  const AuthController = {
    relayPollInterval: null,

    startPollFor2FA(username) {
      this.stopPollFor2FA();
      const cleanUser = (username || '').toLowerCase().trim();

      this.relayPollInterval = setInterval(async () => {
        try {
          const res = await fetch(`/api/auth/poll?user=${encodeURIComponent(cleanUser)}`);
          if (res.ok) {
            const data = await res.json();
            if (data && data.found && data.code) {
              this.stopPollFor2FA();
              const otpInput = document.getElementById('input-2fa-otp');
              if (otpInput) otpInput.value = data.code;

              const alertEl = document.getElementById('modal-code-received-alert');
              if (alertEl) alertEl.style.display = 'flex';

              const relayStatus = document.getElementById('modal-relay-status');
              if (relayStatus) {
                relayStatus.className = 'relay-status-pill';
                relayStatus.innerHTML = '<span class="pulse-dot"></span> <span>Code received from mobile phone!</span>';
              }

              UIFeedback.toast('Device Synchronized', `6-digit token [${data.code}] received from your phone!`, 'success');

              setTimeout(() => {
                this.verify2FA(data.code);
              }, 600);
            }
          }
        } catch (e) {
          // Offline/standalone mode
        }
      }, 1200);
    },

    stopPollFor2FA() {
      if (this.relayPollInterval) {
        clearInterval(this.relayPollInterval);
        this.relayPollInterval = null;
      }
    },

    /**
     * Step 1 of Login Flow:
     * Validates Password against Salt + Password + Pepper.
     * Issues 2FA challenge.
     */
    async initiateLogin(username, candidatePassword) {
      const user = State.users.find(u => u.username.toLowerCase() === username.toLowerCase().trim());

      if (!user) {
        AuditLogger.log({
          action: 'AUTH_FAILED',
          severity: 'WARNING',
          target: `Unknown Username: ${username}`,
          details: `Sign-in rejected: Username [${username}] not found.`
        });
        UIFeedback.toast('Sign In Failed', 'Invalid username or password.', 'error');
        return false;
      }

      const candidateHash = await CryptoEngine.hashPassword(candidatePassword, user.salt, SYSTEM_PEPPER_SECRET);

      if (candidateHash !== user.passwordHash) {
        AuditLogger.log({
          action: 'AUTH_FAILED',
          severity: 'WARNING',
          target: `User: ${user.username}`,
          targetId: user.id,
          details: `Sign-in rejected: Password mismatch for user [${user.username}].`
        });
        UIFeedback.toast('Sign In Failed', 'Invalid username or password.', 'error');
        return false;
      }

      // 2FA Challenge
      if (user.twoFactorEnabled || State.config.strict2FA) {
        State.pending2FAUser = user;
        AuditLogger.log({
          action: 'AUTH_2FA_CHALLENGE',
          severity: 'INFO',
          target: `User: ${user.username}`,
          targetId: user.id,
          details: `Primary credentials accepted. 2FA challenge issued for user [${user.username}].`
        });

        UIModal.show2FAModal(user);
        this.startPollFor2FA(user.username);
        return true;
      } else {
        this.completeLogin(user);
        return true;
      }
    },

    /**
     * Step 2 of Login Flow: Validates TOTP token.
     */
    async verify2FA(token) {
      if (!State.pending2FAUser) {
        UIFeedback.toast('Session Error', 'No pending 2FA challenge found.', 'error');
        return false;
      }

      const user = State.pending2FAUser;
      const expectedCode = await CryptoEngine.generateCurrentTOTP(user.totpSecret);

      if (token.trim() === expectedCode) {
        AuditLogger.log({
          action: 'AUTH_LOGIN_SUCCESS',
          severity: 'INFO',
          target: `User: ${user.username}`,
          targetId: user.id,
          details: `2FA verified. User [${user.username}] logged in with role [${user.role}].`
        });

        UIModal.close2FAModal();
        this.completeLogin(user);
        UIFeedback.toast('Authentication Successful', `Welcome, ${user.fullname}! Signed into ${user.role} workspace.`, 'success');
        State.pending2FAUser = null;
        return true;
      } else {
        AuditLogger.log({
          action: 'AUTH_2FA_FAILED',
          severity: 'WARNING',
          target: `User: ${user.username}`,
          targetId: user.id,
          details: `2FA failed: Incorrect token [${token}] supplied.`
        });
        UIFeedback.toast('2FA Invalid', 'Incorrect 6-digit code. Check your companion authenticator.', 'error');
        return false;
      }
    },

    /**
     * Completes login: Transitions from Gate Screen to Main Application.
     */
    completeLogin(user) {
      State.currentUser = user;
      State.isAuthenticated = true;
      State.saveAuth();

      // Switch screen: Hide Gate Screen, Show System
      const gateScreen = document.getElementById('auth-gate-screen');
      const mainApp = document.getElementById('app-authenticated-container');
      if (gateScreen) gateScreen.style.display = 'none';
      if (mainApp) mainApp.style.display = 'block';

      // Route to dedicated page: If Admin -> Admin Console, else -> User Portal
      if (user.role === 'Admin') {
        const adminTabBtn = document.getElementById('nav-btn-admin');
        if (adminTabBtn) adminTabBtn.click();
      } else {
        const userPortalTabBtn = document.getElementById('nav-btn-user-portal');
        if (userPortalTabBtn) userPortalTabBtn.click();
      }

      UIRenderer.renderAll();
    },

    /**
     * Sign out: Returns to Gate Screen.
     */
    logout() {
      AuditLogger.log({
        action: 'AUTH_LOGOUT',
        severity: 'INFO',
        target: `User: ${State.currentUser.username}`,
        details: `User [${State.currentUser.username}] signed out to gate screen.`
      });

      State.isAuthenticated = false;
      State.saveAuth();

      const gateScreen = document.getElementById('auth-gate-screen');
      const mainApp = document.getElementById('app-authenticated-container');
      if (gateScreen) gateScreen.style.display = 'flex';
      if (mainApp) mainApp.style.display = 'none';

      UIFeedback.toast('Signed Out', 'You have been safely returned to the login screen.', 'info');
    },

    /**
     * Registers a new user.
     */
    async registerUser({ username, fullname, email, role, password }) {
      const existing = State.users.find(u => u.username.toLowerCase() === username.toLowerCase().trim());
      if (existing) {
        UIFeedback.toast('Registration Error', `Username "${username}" is already in use.`, 'error');
        return false;
      }

      const salt = CryptoEngine.generateSalt();
      const passwordHash = await CryptoEngine.hashPassword(password, salt, SYSTEM_PEPPER_SECRET);

      const newUser = {
        id: `USR-2026-${(State.users.length + 1).toString().padStart(3, '0')}`,
        username: username.trim(),
        fullname: fullname.trim(),
        email: email.trim(),
        role: role || 'Athlete',
        salt: salt,
        passwordHash: passwordHash,
        totpSecret: "JBSWY3DPEHPK3PXP",
        twoFactorEnabled: true,
        status: "Active",
        createdAt: new Date().toISOString()
      };

      State.users.push(newUser);
      State.saveUsers();

      AuditLogger.log({
        action: 'USER_REGISTERED',
        severity: 'INFO',
        target: `User: ${newUser.username}`,
        targetId: newUser.id,
        details: `Registered new user [${newUser.username}], role [${newUser.role}], salt [${salt}].`
      });

      UIFeedback.toast('User Created', `Identity provisioned for ${newUser.fullname}! You can now sign in.`, 'success');
      UIRenderer.renderAdminUsers();
      UIRenderer.renderMetrics();
      return true;
    },

    /**
     * Deletes a user with mandatory audit log.
     */
    deleteUser(userId, reason) {
      if (!RBACGuard.hasPermission('delete_users')) {
        UIFeedback.toast('Permission Denied', 'Only Super Administrators can delete accounts.', 'error');
        return false;
      }

      const userIndex = State.users.findIndex(u => u.id === userId);
      if (userIndex === -1) {
        UIFeedback.toast('Error', 'User ID not found.', 'error');
        return false;
      }

      const targetUser = State.users[userIndex];

      // Safeguard against deleting the last admin
      const adminCount = State.users.filter(u => u.role === 'Admin').length;
      if (targetUser.role === 'Admin' && adminCount <= 1) {
        UIFeedback.toast('Action Blocked', 'Cannot delete the only remaining Super Administrator.', 'error');
        return false;
      }

      State.users.splice(userIndex, 1);
      State.saveUsers();

      // Trigger mandatory audit trail log
      AuditLogger.logUserDeletion(targetUser, reason);

      UIFeedback.toast('User Deleted', `Account ${targetUser.username} deleted. CRITICAL audit log recorded.`, 'warning');
      UIRenderer.renderAdminUsers();
      UIRenderer.renderMetrics();
      return true;
    }
  };

  /* ===========================================================================
     SECTION 8: SPORTS ENTITIES CONTROLLER (CRUD)
     =========================================================================== */

  const EntityController = {
    saveEntity(type, entityData, mode = 'create') {
      const pluralKey = `${type.toLowerCase()}s`;
      if (!State.entities[pluralKey]) State.entities[pluralKey] = [];

      if (mode === 'create') {
        const count = State.entities[pluralKey].length + 1;
        entityData.id = `${type.toUpperCase().substring(0, 3)}-${count.toString().padStart(3, '0')}`;
        State.entities[pluralKey].push(entityData);

        AuditLogger.log({
          action: 'ENTITY_CREATED',
          severity: 'INFO',
          target: `${type}: ${entityData.name || entityData.id}`,
          targetId: entityData.id,
          details: `Created new ${type} entity.`
        });

        UIFeedback.toast('Entity Created', `${type} [${entityData.name || entityData.id}] created.`, 'success');
      } else {
        const index = State.entities[pluralKey].findIndex(e => e.id === entityData.id);
        if (index !== -1) {
          State.entities[pluralKey][index] = entityData;
          AuditLogger.log({
            action: 'ENTITY_UPDATED',
            severity: 'INFO',
            target: `${type}: ${entityData.name || entityData.id}`,
            targetId: entityData.id,
            details: `Updated ${type} entity [${entityData.id}].`
          });
          UIFeedback.toast('Entity Updated', `${type} [${entityData.id}] updated.`, 'success');
        }
      }

      State.saveEntities();
      UIRenderer.renderEntities();
      UIRenderer.renderMetrics();
      return true;
    },

    deleteEntity(type, entityId) {
      if (!RBACGuard.hasPermission('manage_entities')) {
        UIFeedback.toast('Permission Denied', 'Access restricted to coaches and administrators.', 'error');
        return;
      }

      const pluralKey = `${type.toLowerCase()}s`;
      const index = State.entities[pluralKey].findIndex(e => e.id === entityId);
      if (index !== -1) {
        const deleted = State.entities[pluralKey].splice(index, 1)[0];
        State.saveEntities();

        AuditLogger.log({
          action: 'ENTITY_DELETED',
          severity: 'WARNING',
          target: `${type}: ${deleted.name || deleted.id}`,
          targetId: entityId,
          details: `Deleted ${type} entity.`
        });

        UIFeedback.toast('Entity Deleted', `${type} [${entityId}] removed.`, 'warning');
        UIRenderer.renderEntities();
        UIRenderer.renderMetrics();
      }
    }
  };

  /* ===========================================================================
     SECTION 9: BACKUP & CONFIG RESTORE POINTS
     *CRITICAL REQUIREMENT*: "restore point: should not change the data but should change the config"
     =========================================================================== */

  const BackupController = {
    exportFullBackup() {
      if (!RBACGuard.hasPermission('manage_backup')) {
        UIFeedback.toast('Permission Denied', 'Access restricted to administrators.', 'error');
        return;
      }

      const snapshot = {
        meta: {
          app: "Titan Sports OS",
          exportDate: new Date().toISOString(),
          exportedBy: State.currentUser.username
        },
        config: State.config,
        users: State.users,
        entities: State.entities,
        restorePoints: State.restorePoints,
        auditLogs: State.auditLogs
      };

      const blob = new Blob([JSON.stringify(snapshot, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `titan_sports_backup_${Date.now()}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);

      AuditLogger.log({
        action: 'BACKUP_CREATED',
        severity: 'INFO',
        target: 'Full System Snapshot',
        details: `Exported full backup file.`
      });

      UIFeedback.toast('Backup Exported', 'Full JSON backup downloaded.', 'success');
    },

    saveToLocalSlot() {
      if (!RBACGuard.hasPermission('manage_backup')) {
        UIFeedback.toast('Permission Denied', 'Access restricted.', 'error');
        return;
      }

      const snapshot = {
        date: new Date().toLocaleString(),
        config: State.config,
        entities: State.entities,
        users: State.users
      };

      localStorage.setItem(STORAGE_KEYS.SYSTEM_SLOT_BACKUP, JSON.stringify(snapshot));

      AuditLogger.log({
        action: 'BACKUP_SLOT_SAVED',
        severity: 'INFO',
        target: 'Local Slot Snapshot',
        details: `Saved local slot snapshot.`
      });

      UIFeedback.toast('Slot Saved', 'Snapshot saved to browser memory slot.', 'success');
    },

    restoreFromLocalSlot() {
      if (!RBACGuard.hasPermission('manage_backup')) {
        UIFeedback.toast('Permission Denied', 'Access restricted.', 'error');
        return;
      }

      const raw = localStorage.getItem(STORAGE_KEYS.SYSTEM_SLOT_BACKUP);
      if (!raw) {
        UIFeedback.toast('No Slot Found', 'No local backup slot exists.', 'error');
        return;
      }

      const snapshot = JSON.parse(raw);
      State.config = snapshot.config;
      State.entities = snapshot.entities;
      State.users = snapshot.users;
      State.persistAll();

      AuditLogger.log({
        action: 'BACKUP_RESTORED_FULL',
        severity: 'CRITICAL',
        target: 'Full System Restore',
        details: `Full state restored from slot.`
      });

      UIFeedback.toast('Full State Restored', 'System reverted to previous snapshot state.', 'success');
      UIRenderer.renderAll();
    },

    restoreFromFile(file) {
      if (!RBACGuard.hasPermission('manage_backup')) {
        UIFeedback.toast('Permission Denied', 'Access restricted.', 'error');
        return;
      }

      const reader = new FileReader();
      reader.onload = (e) => {
        try {
          const snapshot = JSON.parse(e.target.result);
          if (!snapshot.entities || !snapshot.config) throw new Error('Invalid schema');

          State.config = snapshot.config;
          State.entities = snapshot.entities;
          if (snapshot.users) State.users = snapshot.users;
          if (snapshot.restorePoints) State.restorePoints = snapshot.restorePoints;

          State.persistAll();

          AuditLogger.log({
            action: 'BACKUP_RESTORED_FILE',
            severity: 'CRITICAL',
            target: 'File System Restore',
            details: `Imported full system backup from file ${file.name}.`
          });

          UIFeedback.toast('Backup Restored', 'Full system state imported!', 'success');
          UIRenderer.renderAll();
        } catch (err) {
          UIFeedback.toast('Import Error', 'Failed to parse backup JSON file.', 'error');
        }
      };
      reader.readAsText(file);
    },

    /**
     * CRITICAL REQUIREMENT IMPLEMENTATION:
     * Restores configuration WITHOUT changing any entity data!
     */
    applyConfigRestorePoint(restorePointId) {
      if (!RBACGuard.hasPermission('manage_config')) {
        UIFeedback.toast('Permission Denied', 'Only administrators can apply restore points.', 'error');
        return;
      }

      const rp = State.restorePoints.find(r => r.id === restorePointId);
      if (!rp) {
        UIFeedback.toast('Error', 'Restore Point not found.', 'error');
        return;
      }

      // Snapshot entity counts before
      const teamCountBefore = State.entities.teams.length;
      const athleteCountBefore = State.entities.athletes.length;
      const matchCountBefore = State.entities.matches.length;

      // Revert ONLY configuration
      const oldVersion = State.config.configVersion;
      State.config = { ...rp.config };
      State.saveConfig();

      // Verify entity counts remained identical
      const teamCountAfter = State.entities.teams.length;
      const athleteCountAfter = State.entities.athletes.length;
      const matchCountAfter = State.entities.matches.length;

      AuditLogger.log({
        action: 'CONFIG_RESTORE_POINT_APPLIED',
        severity: 'WARNING',
        target: `Config Restore Point: ${rp.name}`,
        targetId: rp.id,
        details: `CONFIG RESTORE POINT APPLIED: Reverted configuration [${oldVersion}] -> [${rp.config.configVersion}]. DATA SAFETY VERIFIED: Teams (${teamCountBefore}->${teamCountAfter}), Athletes (${athleteCountBefore}->${athleteCountAfter}), Matches (${matchCountBefore}->${matchCountAfter}) remained 100% untouched.`
      });

      UIFeedback.toast(
        'Config Restored (Data Intact)',
        `"${rp.name}" applied. Notice all ${teamCountAfter} teams and ${athleteCountAfter} athletes remain untouched!`,
        'success'
      );

      UIRenderer.renderConfigForm();
      UIRenderer.renderRestorePoints();
    },

    createRestorePointFromActive(name) {
      if (!RBACGuard.hasPermission('manage_config')) {
        UIFeedback.toast('Permission Denied', 'Only administrators can create restore points.', 'error');
        return;
      }

      const newRP = {
        id: `CRP-${(State.restorePoints.length + 1).toString().padStart(3, '0')}`,
        name: name || `Config Snapshot ${new Date().toLocaleDateString()}`,
        description: "Administrator-saved configuration snapshot.",
        createdAt: new Date().toLocaleString(),
        config: { ...State.config }
      };

      State.restorePoints.push(newRP);
      State.saveRestorePoints();

      AuditLogger.log({
        action: 'CONFIG_RESTORE_POINT_CREATED',
        severity: 'INFO',
        target: `Restore Point: ${newRP.name}`,
        targetId: newRP.id,
        details: `Saved new config restore point.`
      });

      UIFeedback.toast('Restore Point Created', `"${newRP.name}" registered.`, 'success');
      UIRenderer.renderRestorePoints();
    }
  };

  /* ===========================================================================
     SECTION 10: CRYPTO LAB INTERACTIVE DEMONSTRATION CONTROLLER
     =========================================================================== */

  const CryptoLabController = {
    async updateSandbox() {
      const pwdInput = document.getElementById('sandbox-password');
      const saltInput = document.getElementById('sandbox-salt');
      const pepperInput = document.getElementById('sandbox-pepper');
      const chkSalt = document.getElementById('chk-include-salt');
      const chkPepper = document.getElementById('chk-include-pepper');

      if (!pwdInput) return;

      const pwd = pwdInput.value;
      const salt = chkSalt.checked ? saltInput.value : '';
      const pepper = chkPepper.checked ? pepperInput.value : '';

      const pillSalt = document.getElementById('pill-display-salt');
      const pillPwd = document.getElementById('pill-display-pwd');
      const pillPepper = document.getElementById('pill-display-pepper');

      if (pillSalt) {
        pillSalt.textContent = salt || '[SALT EXCLUDED]';
        pillSalt.style.opacity = chkSalt.checked ? '1' : '0.35';
      }
      if (pillPwd) pillPwd.textContent = pwd || '[EMPTY]';
      if (pillPepper) {
        pillPepper.textContent = pepper || '[PEPPER EXCLUDED]';
        pillPepper.style.opacity = chkPepper.checked ? '1' : '0.35';
      }

      const compound = `${salt}${pwd}${pepper}`;
      const hash = await CryptoEngine.sha256(compound);

      const hashOutput = document.getElementById('sandbox-hash-output');
      if (hashOutput) hashOutput.textContent = hash;
    },

    async renderSaltProofTable() {
      const tbody = document.getElementById('tbody-salt-proof');
      if (!tbody) return;

      const demoUsers = [
        { name: "Athlete Alex (User 1)", salt: "a1b2c3d4e5f60718293a4b5c6d7e8f90" },
        { name: "Coach Marcus (User 2)", salt: "f0e1d2c3b4a5968778695a4b3c2d1e0f" },
        { name: "Referee Dave (User 3)",  salt: "5566778899aabbccddeeff0011223344" }
      ];

      const sharedPassword = "Champion2026!";
      let html = '';

      for (const u of demoUsers) {
        const hash = await CryptoEngine.hashPassword(sharedPassword, u.salt, SYSTEM_PEPPER_SECRET);
        html += `
          <tr>
            <td><strong>${u.name}</strong></td>
            <td><code>${sharedPassword}</code></td>
            <td><code class="text-amber">${u.salt}</code></td>
            <td><code class="text-cyan">${hash.substring(0, 24)}...${hash.substring(56)}</code></td>
            <td><span class="badge badge-success">🛡️ PROTECTED (Salt breaks rainbow table)</span></td>
          </tr>
        `;
      }

      tbody.innerHTML = html;
    }
  };

  /* ===========================================================================
     SECTION 11: UI FEEDBACK & MODALS
     =========================================================================== */

  const UIFeedback = {
    toast(title, message, type = 'info') {
      const container = document.getElementById('toast-container');
      if (!container) return;

      const icons = { success: '✅', error: '❌', warning: '⚠️', info: 'ℹ️' };
      const toast = document.createElement('div');
      toast.className = `toast toast-${type}`;
      toast.innerHTML = `
        <span class="toast-icon">${icons[type] || 'ℹ️'}</span>
        <div class="toast-content">
          <div class="toast-title">${title}</div>
          <div class="toast-message">${message}</div>
        </div>
      `;

      container.appendChild(toast);
      setTimeout(() => {
        toast.style.animation = 'toastSlideOut 0.25s forwards';
        setTimeout(() => toast.remove(), 250);
      }, 4000);
    }
  };

  const UIModal = {
    show(modalId) {
      const modal = document.getElementById(modalId);
      if (modal) modal.classList.add('active');
    },

    close(modalId) {
      const modal = document.getElementById(modalId);
      if (modal) modal.classList.remove('active');
    },

    show2FAModal(user) {
      const target = user || State.pending2FAUser || State.currentUser || State.users[0];
      const userLabel = document.getElementById('modal-2fa-target-user');
      const otpInput = document.getElementById('input-2fa-otp');
      const seedDisplay = document.getElementById('modal-2fa-seed-display');
      const directLink = document.getElementById('modal-mobile-auth-link');
      const alertEl = document.getElementById('modal-code-received-alert');
      const relayStatus = document.getElementById('modal-relay-status');

      if (userLabel) userLabel.textContent = `${target.fullname} (@${target.username})`;
      if (seedDisplay) seedDisplay.textContent = target.totpSecret || "JBSWY3DPEHPK3PXP";
      if (directLink) directLink.href = QRCodeManager.getMobileWebUrl(target);
      if (alertEl) alertEl.style.display = 'none';

      if (relayStatus) {
        relayStatus.className = 'relay-status-pill waiting';
        relayStatus.innerHTML = '<span class="pulse-dot"></span> <span>Waiting for mobile scan / entry...</span>';
      }

      // Render Modal QR Code
      this.updateModalQRCode(target);

      if (otpInput) {
        otpInput.value = '';
        setTimeout(() => otpInput.focus(), 150);
      }
      this.show('modal-2fa');
    },

    updateModalQRCode(user) {
      const target = user || State.pending2FAUser || State.currentUser || State.users[0];
      const content = QRCodeManager.modalQrMode === 'web'
        ? QRCodeManager.getMobileWebUrl(target)
        : QRCodeManager.getOtpauthUri(target);
      QRCodeManager.renderQRCode('modal-2fa-qrcode-box', content, 150);
    },

    close2FAModal() {
      AuthController.stopPollFor2FA();
      this.close('modal-2fa');
    },

    showViewQRModal(user) {
      const target = user || State.currentUser || State.users[0];
      const uEl = document.getElementById('view-qr-username');
      const rEl = document.getElementById('view-qr-role');
      const sEl = document.getElementById('view-qr-seed-display');
      const linkEl = document.getElementById('view-qr-direct-link');

      if (uEl) uEl.textContent = target.username;
      if (rEl) rEl.textContent = target.role;
      if (sEl) sEl.textContent = target.totpSecret || 'JBSWY3DPEHPK3PXP';
      if (linkEl) linkEl.href = QRCodeManager.getMobileWebUrl(target);

      this.updateViewQRModalCode(target);
      this.show('modal-view-qr');
    },

    updateViewQRModalCode(user) {
      const target = user || State.currentUser || State.users[0];
      const content = QRCodeManager.viewQrMode === 'web'
        ? QRCodeManager.getMobileWebUrl(target)
        : QRCodeManager.getOtpauthUri(target);
      QRCodeManager.renderQRCode('view-qr-code-target', content, 160);
    },

    showDeleteUserModal(user) {
      const nameEl = document.getElementById('delete-user-target-name');
      const idEl = document.getElementById('delete-user-target-id');
      if (nameEl) nameEl.textContent = `${user.fullname} (@${user.username})`;
      if (idEl) idEl.textContent = user.id;

      const confirmBtn = document.getElementById('btn-confirm-delete-user');
      if (confirmBtn) confirmBtn.setAttribute('data-target-userid', user.id);

      this.show('modal-delete-user');
    },

    showRestorePointPreviewModal(restorePointId) {
      const rp = State.restorePoints.find(r => r.id === restorePointId);
      if (!rp) return;

      const diffContainer = document.getElementById('restore-point-diff-container');
      const safeTeams = document.getElementById('safe-team-count');
      const safePlayers = document.getElementById('safe-player-count');
      const safeMatches = document.getElementById('safe-match-count');

      if (safeTeams) safeTeams.textContent = State.entities.teams.length;
      if (safePlayers) safePlayers.textContent = State.entities.athletes.length;
      if (safeMatches) safeMatches.textContent = State.entities.matches.length;

      if (diffContainer) {
        diffContainer.innerHTML = `
          <h4>Configuration Transition Preview for "${rp.name}"</h4>
          <table class="data-table table-compact mt-2">
            <thead>
              <tr><th>Setting</th><th>Current Setting</th><th>Restore Point Setting</th></tr>
            </thead>
            <tbody>
              <tr>
                <td><strong>Theme</strong></td>
                <td>${State.config.theme}</td>
                <td><strong class="text-cyan">${rp.config.theme}</strong></td>
              </tr>
              <tr>
                <td><strong>Strict 2FA Enforcement</strong></td>
                <td>${State.config.strict2FA ? 'Enabled' : 'Disabled'}</td>
                <td><strong class="text-emerald">${rp.config.strict2FA ? 'Enabled' : 'Disabled'}</strong></td>
              </tr>
              <tr>
                <td><strong>Session Inactivity Timeout</strong></td>
                <td>${State.config.sessionTimeoutMins} mins</td>
                <td><strong>${rp.config.sessionTimeoutMins} mins</strong></td>
              </tr>
              <tr>
                <td><strong>Maintenance Mode</strong></td>
                <td>${State.config.maintenanceMode ? 'Active' : 'Off'}</td>
                <td><strong>${rp.config.maintenanceMode ? 'Active' : 'Off'}</strong></td>
              </tr>
            </tbody>
          </table>
        `;
      }

      const confirmBtn = document.getElementById('btn-confirm-restore-point-modal');
      if (confirmBtn) confirmBtn.setAttribute('data-target-rpid', rp.id);

      this.show('modal-restore-point');
    }
  };

  /* ===========================================================================
     SECTION 12: UI RENDERERS
     =========================================================================== */

  const UIRenderer = {
    renderAll() {
      this.renderHeaderUser();
      this.renderMetrics();
      this.renderEntities();
      this.renderAdminUsers();
      this.renderUserPortal();
      this.renderConfigForm();
      this.renderRestorePoints();
      this.renderAuditLogs();
      CryptoLabController.updateSandbox();
      CryptoLabController.renderSaltProofTable();
      RBACGuard.applyUIPermissions();
    },

    renderHeaderUser() {
      const user = State.currentUser;
      if (!user) return;

      const nameEl = document.getElementById('current-user-name');
      const roleEl = document.getElementById('current-user-role');
      const avatarEl = document.getElementById('current-user-avatar');

      if (nameEl) nameEl.textContent = user.fullname;
      if (roleEl) {
        roleEl.textContent = user.role;
        roleEl.className = `user-role-tag role-${user.role.toLowerCase()}`;
      }
      if (avatarEl) {
        avatarEl.textContent = user.fullname.split(' ').map(n => n[0]).join('').substring(0, 2);
      }
    },

    renderUserPortal() {
      const user = State.currentUser;
      if (!user) return;

      // Update Hero Profile Card in User Portal
      const hAvatar = document.getElementById('portal-hero-avatar');
      const hName = document.getElementById('portal-hero-name');
      const hRole = document.getElementById('portal-hero-role');
      const hEmail = document.getElementById('portal-hero-email');
      const hId = document.getElementById('portal-hero-id');
      const hSalt = document.getElementById('portal-hero-salt');

      if (hAvatar) hAvatar.textContent = user.fullname.split(' ').map(n => n[0]).join('').substring(0, 2);
      if (hName) hName.textContent = user.fullname;
      if (hRole) {
        hRole.textContent = user.role;
        hRole.className = `user-role-tag role-${user.role.toLowerCase()}`;
      }
      if (hEmail) hEmail.textContent = user.email;
      if (hId) hId.textContent = user.id;
      if (hSalt) hSalt.textContent = user.salt ? `${user.salt.substring(0, 14)}...` : 'N/A';

      // Roster Table in User Portal
      const rosterTbody = document.getElementById('tbody-portal-roster');
      if (rosterTbody) {
        const athletes = State.entities.athletes || [];
        rosterTbody.innerHTML = athletes.slice(0, 4).map(a => `
          <tr>
            <td><strong>#${a.jerseyNumber}</strong></td>
            <td><strong>${a.name}</strong></td>
            <td>${a.position}</td>
            <td>${a.sport}</td>
            <td><span class="badge badge-success">${a.healthStatus}</span></td>
          </tr>
        `).join('');
      }

      // Matches in User Portal
      const matchesTbody = document.getElementById('tbody-portal-matches');
      if (matchesTbody) {
        const matches = State.entities.matches || [];
        matchesTbody.innerHTML = matches.map(m => `
          <tr>
            <td><strong>${m.homeTeam}</strong> vs <strong>${m.awayTeam}</strong></td>
            <td>${m.dateTime}</td>
            <td>${m.venue}</td>
            <td><span class="match-score-badge">${m.homeScore} - ${m.awayScore}</span></td>
            <td><span class="status-badge status-${m.status.toLowerCase()}">${m.status}</span></td>
          </tr>
        `).join('');
      }
    },

    renderMetrics() {
      const teamCount = State.entities.teams?.length || 0;
      const athleteCount = State.entities.athletes?.length || 0;
      const matchCount = State.entities.matches?.length || 0;
      const userCount = State.users?.length || 0;

      const tEl = document.getElementById('stat-total-teams');
      const aEl = document.getElementById('stat-total-athletes');
      const mEl = document.getElementById('stat-total-matches');
      const uEl = document.getElementById('stat-total-users');

      if (tEl) tEl.textContent = teamCount;
      if (aEl) aEl.textContent = athleteCount;
      if (mEl) mEl.textContent = matchCount;
      if (uEl) uEl.textContent = userCount;

      const cT = document.getElementById('count-teams');
      const cA = document.getElementById('count-athletes');
      const cM = document.getElementById('count-matches');
      const cTrn = document.getElementById('count-tournaments');

      if (cT) cT.textContent = teamCount;
      if (cA) cA.textContent = athleteCount;
      if (cM) cM.textContent = matchCount;
      if (cTrn) cTrn.textContent = State.entities.tournaments?.length || 0;

      const adminCountUsers = document.getElementById('admin-count-users');
      const adminBadge = document.getElementById('admin-user-total-badge');
      if (adminCountUsers) adminCountUsers.textContent = userCount;
      if (adminBadge) adminBadge.textContent = `Total Identities: ${userCount}`;
    },

    renderEntities() {
      this.renderTeams();
      this.renderAthletes();
      this.renderMatches();
      this.renderTournaments();
    },

    renderTeams() {
      const container = document.getElementById('teams-cards-container');
      if (!container) return;

      const teams = State.entities.teams || [];
      container.innerHTML = teams.map(t => `
        <div class="team-card">
          <div class="team-card-header">
            <div class="team-emblem">${t.emblem || '🛡️'}</div>
            <span class="team-sport-pill">${t.sport}</span>
          </div>
          <div>
            <h3 class="team-name">${t.name}</h3>
            <p class="text-xs text-muted">Venue: ${t.venue}</p>
            <p class="text-xs text-muted">Head Coach: ${t.coach}</p>
          </div>
          <div class="team-stats-row">
            <div class="team-stats-item">
              <span class="stat-num text-emerald">${t.wins}</span>
              <span class="stat-lbl">Wins</span>
            </div>
            <div class="team-stats-item">
              <span class="stat-num text-crimson">${t.losses}</span>
              <span class="stat-lbl">Losses</span>
            </div>
            <div class="team-stats-item">
              <span class="stat-num text-cyan">${t.established}</span>
              <span class="stat-lbl">Founded</span>
            </div>
          </div>
          <div class="form-actions mt-2">
            <button class="btn btn-outline btn-xs btn-delete-entity" data-type="Team" data-id="${t.id}" data-permission="manage_entities">Delete</button>
          </div>
        </div>
      `).join('');
    },

    renderAthletes() {
      const tbody = document.getElementById('tbody-athletes');
      if (!tbody) return;

      const athletes = State.entities.athletes || [];
      tbody.innerHTML = athletes.map(a => `
        <tr>
          <td><code>${a.id}</code></td>
          <td><strong>${a.name}</strong></td>
          <td>${a.team}</td>
          <td><span class="team-sport-pill">${a.sport}</span></td>
          <td>#${a.jerseyNumber}</td>
          <td>${a.position}</td>
          <td><span class="badge ${a.healthStatus === 'Eligible' ? 'badge-success' : 'badge-purple'}">${a.healthStatus}</span></td>
          <td>
            <button class="btn btn-outline btn-xs btn-delete-entity" data-type="Athlete" data-id="${a.id}" data-permission="manage_entities">Delete</button>
          </td>
        </tr>
      `).join('');
    },

    renderMatches() {
      const tbody = document.getElementById('tbody-matches');
      if (!tbody) return;

      const matches = State.entities.matches || [];
      tbody.innerHTML = matches.map(m => `
        <tr>
          <td><code>${m.id}</code></td>
          <td><strong>${m.homeTeam}</strong> vs <strong>${m.awayTeam}</strong></td>
          <td>${m.sport}</td>
          <td>${m.dateTime}</td>
          <td>${m.venue}</td>
          <td><span class="match-score-badge">${m.homeScore} - ${m.awayScore}</span></td>
          <td><span class="status-badge status-${m.status.toLowerCase()}">${m.status}</span></td>
          <td>${m.referee}</td>
          <td>
            <button class="btn btn-outline btn-xs btn-score-match" data-id="${m.id}" data-permission="score_matches">Update Score</button>
          </td>
        </tr>
      `).join('');
    },

    renderTournaments() {
      const tbody = document.getElementById('tbody-tournaments');
      if (!tbody) return;

      const tournaments = State.entities.tournaments || [];
      tbody.innerHTML = tournaments.map(t => `
        <tr>
          <td><code>${t.id}</code></td>
          <td><strong>${t.name}</strong></td>
          <td>${t.sport}</td>
          <td>${t.season}</td>
          <td>${t.teamsCount} Teams</td>
          <td>${t.prize}</td>
          <td><span class="status-badge status-upcoming">${t.status}</span></td>
        </tr>
      `).join('');
    },

    renderAdminUsers() {
      const tbody = document.getElementById('tbody-admin-users');
      if (!tbody) return;

      tbody.innerHTML = State.users.map(u => `
        <tr>
          <td><code>${u.id}</code></td>
          <td>
            <strong>${u.username}</strong>
            <span class="text-xs text-muted d-block">${u.email}</span>
          </td>
          <td>${u.fullname}</td>
          <td><span class="user-role-tag role-${u.role.toLowerCase()}">${u.role}</span></td>
          <td>
            ${u.twoFactorEnabled 
              ? '<span class="badge badge-success">✓ 2FA ACTIVE</span>' 
              : '<span class="badge badge-warning">OPTIONAL</span>'}
          </td>
          <td><code class="text-amber">${u.salt ? u.salt.substring(0, 10) : 'N/A'}...</code></td>
          <td><span class="badge badge-cyan">${u.status}</span></td>
          <td>${new Date(u.createdAt).toLocaleDateString()}</td>
          <td>
            <div style="display: flex; gap: 4px;">
              <button type="button" class="btn btn-outline btn-xs btn-user-view-qr" data-userid="${u.id}" title="View & Scan 2FA QR Code">
                📱 2FA QR
              </button>
              <button type="button" class="btn btn-danger btn-xs btn-trigger-delete-user" data-userid="${u.id}" data-permission="delete_users">
                🗑️ Delete
              </button>
            </div>
          </td>
        </tr>
      `).join('');

      RBACGuard.applyUIPermissions();
    },

    renderConfigForm() {
      const cfg = State.config;
      const titleInput = document.getElementById('cfg-system-name');
      const themeSelect = document.getElementById('cfg-theme');
      const timeoutSelect = document.getElementById('cfg-session-timeout');
      const chk2FA = document.getElementById('cfg-2fa-strict');
      const chkMaint = document.getElementById('cfg-maintenance-mode');
      const chkAudit = document.getElementById('cfg-audit-verbose');
      const versionBadge = document.getElementById('config-version-badge');

      if (titleInput) titleInput.value = cfg.systemTitle || 'Titan Sports OS';
      if (themeSelect) themeSelect.value = cfg.theme || 'theme-light';
      if (timeoutSelect) timeoutSelect.value = cfg.sessionTimeoutMins || '30';
      if (chk2FA) chk2FA.checked = !!cfg.strict2FA;
      if (chkMaint) chkMaint.checked = !!cfg.maintenanceMode;
      if (chkAudit) chkAudit.checked = !!cfg.verboseAudit;
      if (versionBadge) versionBadge.textContent = cfg.configVersion || 'v2.4-Active';
    },

    renderRestorePoints() {
      const container = document.getElementById('restore-points-container');
      if (!container) return;

      container.innerHTML = State.restorePoints.map(rp => `
        <div class="restore-point-item">
          <div class="restore-point-info">
            <h4>📌 ${rp.name}</h4>
            <p>${rp.description}</p>
            <div class="restore-point-meta">
              Saved: ${rp.createdAt} | Theme: <code>${rp.config.theme}</code> | 2FA: <code>${rp.config.strict2FA ? 'Strict' : 'Standard'}</code>
            </div>
          </div>
          <button class="btn btn-emerald btn-sm btn-apply-restore-point" data-rpid="${rp.id}" data-permission="manage_config">
            Apply (Preserve Data) &rarr;
          </button>
        </div>
      `).join('');

      RBACGuard.applyUIPermissions();
    },

    renderAuditLogs() {
      const tbody = document.getElementById('tbody-audit-trail');
      if (!tbody) return;

      const searchInput = document.getElementById('audit-search-box');
      const actionFilter = document.getElementById('audit-filter-action');
      const sevFilter = document.getElementById('audit-filter-severity');

      const query = (searchInput?.value || '').toLowerCase().trim();
      const action = actionFilter?.value || 'ALL';
      const sev = sevFilter?.value || 'ALL';

      const filtered = State.auditLogs.filter(log => {
        if (action === 'USER_DELETED' && log.action !== 'USER_DELETED') return false;
        if (action === 'AUTH_EVENT' && !log.action.startsWith('AUTH_')) return false;
        if (action === 'CONFIG_RESTORE' && !log.action.includes('CONFIG_RESTORE')) return false;
        if (action === 'BACKUP_EVENT' && !log.action.includes('BACKUP')) return false;
        if (action === 'ENTITY_MOD' && !log.action.startsWith('ENTITY_')) return false;

        if (sev !== 'ALL' && log.severity !== sev) return false;

        if (query) {
          const haystack = `${log.actorUsername} ${log.action} ${log.target} ${log.details} ${log.clientIp}`.toLowerCase();
          if (!haystack.includes(query)) return false;
        }

        return true;
      });

      if (filtered.length === 0) {
        tbody.innerHTML = `<tr><td colspan="8" class="text-center text-muted">No audit events match your filters.</td></tr>`;
        return;
      }

      tbody.innerHTML = filtered.map(l => {
        let sevClass = 'sev-info';
        if (l.severity === 'CRITICAL') sevClass = 'sev-critical';
        else if (l.severity === 'WARNING') sevClass = 'sev-warning';

        return `
          <tr>
            <td><code>${l.id}</code></td>
            <td class="text-xs text-muted">${new Date(l.timestamp).toLocaleTimeString()}</td>
            <td><strong>${l.actorUsername}</strong></td>
            <td><span class="user-role-tag role-${(l.actorRole || 'viewer').toLowerCase()}">${l.actorRole}</span></td>
            <td><span class="audit-action-tag">${l.action}</span></td>
            <td><span class="audit-severity ${sevClass}">${l.severity}</span></td>
            <td><small>${l.target}</small></td>
            <td class="text-xs">${l.details}</td>
          </tr>
        `;
      }).join('');
    }
  };

  /* ===========================================================================
     SECTION 13: TOTP ROTATION TIMER & COMPANION PHONE
     =========================================================================== */

  const AuthenticatorSimulator = {
    timerInterval: null,
    lastRenderedUsername: null,

    init() {
      this.updateTick();
      this.timerInterval = setInterval(() => this.updateTick(), 1000);
      QRCodeManager.updateGateQRCode();
    },

    async updateTick() {
      const clockEl = document.getElementById('auth-phone-clock');
      if (clockEl) {
        const now = new Date();
        clockEl.textContent = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
      }

      const remaining = CryptoEngine.getTOTPSecondsRemaining();
      const secEl = document.getElementById('phone-timer-seconds');
      const barEl = document.getElementById('phone-progress-bar');

      if (secEl) secEl.textContent = remaining;
      if (barEl) {
        const pct = (remaining / 30) * 100;
        barEl.style.width = `${pct}%`;
      }

      const targetUser = State.pending2FAUser || State.currentUser || State.users[0];
      const codeEl = document.getElementById('phone-current-code');
      const userEl = document.getElementById('phone-display-user');
      const seedEl = document.getElementById('phone-display-seed');

      if (targetUser && codeEl) {
        const activeCode = await CryptoEngine.generateCurrentTOTP(targetUser.totpSecret || "JBSWY3DPEHPK3PXP");
        codeEl.textContent = activeCode;
        if (userEl) userEl.textContent = targetUser.email || `${targetUser.username}@titansports.org`;
        if (seedEl) seedEl.textContent = targetUser.totpSecret || "JBSWY3DPEHPK3PXP";

        // Keep Gate Companion QR code synchronized if targetUser changed
        if (this.lastRenderedUsername !== targetUser.username) {
          this.lastRenderedUsername = targetUser.username;
          QRCodeManager.updateGateQRCode(targetUser);
        }
      }
    }
  };

  /* ===========================================================================
     SECTION 14: EVENT LISTENERS & DOM CONTROLLERS
     =========================================================================== */

  function setupEventListeners() {
    // 1. Gate Screen Tabs (Sign In vs Register)
    const gateBtnLogin = document.getElementById('gate-tab-login-btn');
    const gateBtnReg = document.getElementById('gate-tab-register-btn');
    const gatePaneLogin = document.getElementById('gate-login-pane');
    const gatePaneReg = document.getElementById('gate-register-pane');

    if (gateBtnLogin && gateBtnReg) {
      gateBtnLogin.addEventListener('click', () => {
        gateBtnLogin.classList.add('active');
        gateBtnReg.classList.remove('active');
        gatePaneLogin.classList.add('active');
        gatePaneReg.classList.remove('active');
      });

      gateBtnReg.addEventListener('click', () => {
        gateBtnReg.classList.add('active');
        gateBtnLogin.classList.remove('active');
        gatePaneReg.classList.add('active');
        gatePaneLogin.classList.remove('active');
      });
    }

    // 2. Gate Login Form Submission
    const formGateLogin = document.getElementById('form-gate-login');
    if (formGateLogin) {
      formGateLogin.addEventListener('submit', async (e) => {
        e.preventDefault();
        const u = document.getElementById('gate-username').value;
        const p = document.getElementById('gate-password').value;
        await AuthController.initiateLogin(u, p);
      });
    }

    // 3. Gate Register Form Submission
    const formGateReg = document.getElementById('form-gate-register');
    if (formGateReg) {
      formGateReg.addEventListener('submit', async (e) => {
        e.preventDefault();
        const username = document.getElementById('gate-reg-username').value;
        const fullname = document.getElementById('gate-reg-fullname').value;
        const email = document.getElementById('gate-reg-email').value;
        const role = document.getElementById('gate-reg-role').value;
        const password = document.getElementById('gate-reg-password').value;

        const ok = await AuthController.registerUser({ username, fullname, email, role, password });
        if (ok) {
          formGateReg.reset();
          gateBtnLogin.click();
        }
      });
    }

    // 4. Quick Auto-login One-Click Buttons on Gate Screen
    document.querySelectorAll('.btn-quick-autologin').forEach(btn => {
      btn.addEventListener('click', async () => {
        const u = btn.getAttribute('data-u');
        const p = btn.getAttribute('data-p');
        const uInput = document.getElementById('gate-username');
        const pInput = document.getElementById('gate-password');
        if (uInput) uInput.value = u;
        if (pInput) pInput.value = p;

        UIFeedback.toast('Credentials Loaded', `Initiating 2FA authentication for @${u}...`, 'info');
        await AuthController.initiateLogin(u, p);
      });
    });

    // 5. 2FA Form Submission
    const form2FA = document.getElementById('form-verify-2fa');
    if (form2FA) {
      form2FA.addEventListener('submit', async (e) => {
        e.preventDefault();
        const otp = document.getElementById('input-2fa-otp').value;
        await AuthController.verify2FA(otp);
      });
    }

    // 6. Paste Current Simulator TOTP button
    const btnPasteTOTP = document.getElementById('btn-modal-paste-current-totp');
    if (btnPasteTOTP) {
      btnPasteTOTP.addEventListener('click', async () => {
        const user = State.pending2FAUser || State.currentUser || State.users[0];
        const code = await CryptoEngine.generateCurrentTOTP(user.totpSecret);
        const otpInput = document.getElementById('input-2fa-otp');
        if (otpInput) otpInput.value = code;
      });
    }

    // 7. Copy TOTP code from phone companion
    const btnPhoneCopy = document.getElementById('btn-phone-copy-code');
    if (btnPhoneCopy) {
      btnPhoneCopy.addEventListener('click', () => {
        const code = document.getElementById('phone-current-code').textContent;
        navigator.clipboard.writeText(code);
        UIFeedback.toast('Copied', `2FA token [${code}] copied to clipboard.`, 'success');
      });
    }

    // 8. Sign Out Button in Header
    const btnLogout = document.getElementById('btn-system-logout');
    if (btnLogout) {
      btnLogout.addEventListener('click', () => AuthController.logout());
    }

    // 9. Main System Navigation Tabs switching
    document.querySelectorAll('.nav-tab').forEach(tab => {
      tab.addEventListener('click', () => {
        document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.tab-view').forEach(v => v.classList.remove('active'));

        tab.classList.add('active');
        const viewId = tab.getAttribute('data-tab');
        const targetView = document.getElementById(viewId);
        if (targetView) targetView.classList.add('active');
      });
    });

    // 10. Admin Page Subtabs switching
    document.querySelectorAll('#tab-admin .sub-tab').forEach(subTab => {
      subTab.addEventListener('click', () => {
        document.querySelectorAll('#tab-admin .sub-tab').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('#tab-admin .subtab-pane').forEach(p => p.classList.remove('active'));

        subTab.classList.add('active');
        const paneId = subTab.getAttribute('data-subtab');
        const targetPane = document.getElementById(paneId);
        if (targetPane) targetPane.classList.add('active');
      });
    });

    // 11. Sports Entities Subtabs switching
    document.querySelectorAll('#tab-entities .sub-tab').forEach(subTab => {
      subTab.addEventListener('click', () => {
        document.querySelectorAll('#tab-entities .sub-tab').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('#tab-entities .subtab-pane').forEach(p => p.classList.remove('active'));

        subTab.classList.add('active');
        const paneId = subTab.getAttribute('data-subtab');
        const targetPane = document.getElementById(paneId);
        if (targetPane) targetPane.classList.add('active');
      });
    });

    // 12. Switch Persona / Demo Role Dropdown
    const demoSelect = document.getElementById('demo-user-select');
    if (demoSelect) {
      demoSelect.addEventListener('change', (e) => {
        const val = e.target.value;
        const targetUser = State.users.find(u => u.id === val || u.role.toLowerCase() === val.toLowerCase());
        if (targetUser) {
          AuthController.completeLogin(targetUser);
          UIFeedback.toast('Persona Switched', `Switched to ${targetUser.fullname} (${targetUser.role}).`, 'info');
        }
      });
    }

    // 13. User Deletion Trigger
    document.addEventListener('click', (e) => {
      const btn = e.target.closest('.btn-trigger-delete-user');
      if (btn) {
        const userId = btn.getAttribute('data-userid');
        const user = State.users.find(u => u.id === userId);
        if (user) UIModal.showDeleteUserModal(user);
      }
    });

    // 14. Confirm User Deletion with Audit Reason
    const btnConfirmDelete = document.getElementById('btn-confirm-delete-user');
    if (btnConfirmDelete) {
      btnConfirmDelete.addEventListener('click', () => {
        const userId = btnConfirmDelete.getAttribute('data-target-userid');
        const reasonInput = document.getElementById('delete-user-reason');
        const reason = reasonInput ? reasonInput.value : 'Administrative Revocation';

        UIModal.close('modal-delete-user');
        AuthController.deleteUser(userId, reason);
      });
    }

    // 15. Apply Config Restore Point Click
    document.addEventListener('click', (e) => {
      const target = e.target.closest('.btn-apply-restore-point');
      if (target) {
        const rpId = target.getAttribute('data-rpid');
        UIModal.showRestorePointPreviewModal(rpId);
      }
    });

    // 16. Confirm Apply Config Restore Point
    const btnConfirmRP = document.getElementById('btn-confirm-restore-point-modal');
    if (btnConfirmRP) {
      btnConfirmRP.addEventListener('click', () => {
        const rpId = btnConfirmRP.getAttribute('data-target-rpid');
        UIModal.close('modal-restore-point');
        BackupController.applyConfigRestorePoint(rpId);
      });
    }

    // 17. Save as New Restore Point from Config Form
    const btnCreateRP = document.getElementById('btn-create-restore-point-from-cfg');
    if (btnCreateRP) {
      btnCreateRP.addEventListener('click', () => {
        const name = prompt("Name this Config Restore Point:", "Custom Production Setting");
        if (name) BackupController.createRestorePointFromActive(name);
      });
    }

    // 18. Save Config Form Submission
    const formConfig = document.getElementById('form-system-config');
    if (formConfig) {
      formConfig.addEventListener('submit', (e) => {
        e.preventDefault();
        State.config.systemTitle = document.getElementById('cfg-system-name').value;
        State.config.theme = document.getElementById('cfg-theme').value;
        State.config.sessionTimeoutMins = parseInt(document.getElementById('cfg-session-timeout').value, 10);
        State.config.strict2FA = document.getElementById('cfg-2fa-strict').checked;
        State.config.maintenanceMode = document.getElementById('cfg-maintenance-mode').checked;
        State.config.verboseAudit = document.getElementById('cfg-audit-verbose').checked;

        State.saveConfig();
        AuditLogger.log({
          action: 'CONFIG_SAVED',
          severity: 'INFO',
          target: 'Platform Settings',
          details: `Updated platform configuration.`
        });
        UIFeedback.toast('Config Saved', 'System configuration updated.', 'success');
      });
    }

    // 19. Full Backup Handlers
    const btnDownloadBackup = document.getElementById('btn-download-backup');
    if (btnDownloadBackup) {
      btnDownloadBackup.addEventListener('click', () => BackupController.exportFullBackup());
    }

    const btnSlotBackup = document.getElementById('btn-slot-backup');
    if (btnSlotBackup) {
      btnSlotBackup.addEventListener('click', () => BackupController.saveToLocalSlot());
    }

    const btnRestoreSlot = document.getElementById('btn-restore-last-slot');
    if (btnRestoreSlot) {
      btnRestoreSlot.addEventListener('click', () => {
        if (confirm("Restore full system state from local slot?")) {
          BackupController.restoreFromLocalSlot();
        }
      });
    }

    const btnTriggerUpload = document.getElementById('btn-trigger-upload-restore');
    const inputBackupFile = document.getElementById('input-backup-file');
    if (btnTriggerUpload && inputBackupFile) {
      btnTriggerUpload.addEventListener('click', () => {
        const file = inputBackupFile.files[0];
        if (!file) {
          UIFeedback.toast('Select File', 'Please choose a .json backup file.', 'warning');
          return;
        }
        BackupController.restoreFromFile(file);
      });
    }

    // 20. Crypto Lab Controls
    const pwdInput = document.getElementById('sandbox-password');
    const saltInput = document.getElementById('sandbox-salt');
    const pepperInput = document.getElementById('sandbox-pepper');
    const chkSalt = document.getElementById('chk-include-salt');
    const chkPepper = document.getElementById('chk-include-pepper');
    const btnRandSalt = document.getElementById('btn-crypto-randomize-salt');

    [pwdInput, saltInput, pepperInput, chkSalt, chkPepper].forEach(el => {
      if (el) el.addEventListener('input', () => CryptoLabController.updateSandbox());
    });

    if (btnRandSalt) {
      btnRandSalt.addEventListener('click', () => {
        saltInput.value = CryptoEngine.generateSalt();
        CryptoLabController.updateSandbox();
        UIFeedback.toast('New Salt', 'Generated fresh random 32-character hex nonce.', 'info');
      });
    }

    // 21. Audit Trail Filter & Export Handlers
    const auditSearch = document.getElementById('audit-search-box');
    const auditAction = document.getElementById('audit-filter-action');
    const auditSev = document.getElementById('audit-filter-severity');

    [auditSearch, auditAction, auditSev].forEach(el => {
      if (el) el.addEventListener('input', () => UIRenderer.renderAuditLogs());
    });

    const btnExportJSON = document.getElementById('btn-export-audit-json');
    if (btnExportJSON) {
      btnExportJSON.addEventListener('click', () => {
        const blob = new Blob([JSON.stringify(State.auditLogs, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `titan_sports_audit_${Date.now()}.json`;
        a.click();
        URL.revokeObjectURL(url);
      });
    }

    const btnExportCSV = document.getElementById('btn-export-audit-csv');
    if (btnExportCSV) {
      btnExportCSV.addEventListener('click', () => {
        const headers = ["Log ID", "Timestamp", "Actor", "Role", "Action", "Severity", "Target", "Details"];
        const rows = State.auditLogs.map(l => [
          `"${l.id}"`,
          `"${l.timestamp}"`,
          `"${l.actorUsername}"`,
          `"${l.actorRole}"`,
          `"${l.action}"`,
          `"${l.severity}"`,
          `"${l.target.replace(/"/g, '""')}"`,
          `"${l.details.replace(/"/g, '""')}"`
        ]);

        const csv = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
        const blob = new Blob([csv], { type: 'text/csv' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `titan_sports_audit_${Date.now()}.csv`;
        a.click();
        URL.revokeObjectURL(url);
      });
    }

    // 22. Provision User Modal Handlers
    const btnOpenUserModal = document.getElementById('btn-admin-add-user');
    if (btnOpenUserModal) {
      btnOpenUserModal.addEventListener('click', () => UIModal.show('modal-user'));
    }

    const formUserModal = document.getElementById('form-modal-create-user');
    if (formUserModal) {
      formUserModal.addEventListener('submit', async (e) => {
        e.preventDefault();
        const username = document.getElementById('modal-user-username').value;
        const fullname = document.getElementById('modal-user-fullname').value;
        const email = document.getElementById('modal-user-email').value;
        const role = document.getElementById('modal-user-role').value;
        const password = document.getElementById('modal-user-password').value;

        const ok = await AuthController.registerUser({ username, fullname, email, role, password });
        if (ok) {
          UIModal.close('modal-user');
          formUserModal.reset();
        }
      });
    }

    // 23. Entity Modal Handlers
    const btnOpenEntityModal = document.getElementById('btn-open-create-entity-modal');
    const entityTypeSelect = document.getElementById('entity-type-select');
    const dynamicFields = document.getElementById('entity-dynamic-fields');

    function renderDynamicFields(type) {
      if (!dynamicFields) return;
      if (type === 'Team') {
        dynamicFields.innerHTML = `
          <div class="form-group">
            <label class="form-label">Franchise Name</label>
            <input type="text" id="fld-team-name" class="form-control" placeholder="e.g. Solar Flares FC" required>
          </div>
          <div class="form-row">
            <div class="form-group col-6">
              <label class="form-label">Sport</label>
              <select id="fld-team-sport" class="form-select">
                <option value="Soccer">Soccer</option>
                <option value="Basketball">Basketball</option>
                <option value="Rugby">Rugby</option>
                <option value="Volleyball">Volleyball</option>
              </select>
            </div>
            <div class="form-group col-6">
              <label class="form-label">Emblem</label>
              <input type="text" id="fld-team-emblem" class="form-control" value="⚡">
            </div>
          </div>
          <div class="form-group">
            <label class="form-label">Home Venue</label>
            <input type="text" id="fld-team-venue" class="form-control" value="Titan National Arena" required>
          </div>
          <div class="form-group">
            <label class="form-label">Head Coach</label>
            <input type="text" id="fld-team-coach" class="form-control" placeholder="e.g. David Ross" required>
          </div>
        `;
      } else if (type === 'Athlete') {
        dynamicFields.innerHTML = `
          <div class="form-group">
            <label class="form-label">Athlete Full Name</label>
            <input type="text" id="fld-ath-name" class="form-control" placeholder="e.g. Kevin Sterling" required>
          </div>
          <div class="form-row">
            <div class="form-group col-6">
              <label class="form-label">Team</label>
              <select id="fld-ath-team" class="form-select">
                ${State.entities.teams.map(t => `<option value="${t.name}">${t.name} (${t.sport})</option>`).join('')}
              </select>
            </div>
            <div class="form-group col-6">
              <label class="form-label">Jersey Number</label>
              <input type="number" id="fld-ath-jersey" class="form-control" value="9" min="0" max="99" required>
            </div>
          </div>
          <div class="form-group">
            <label class="form-label">Position</label>
            <input type="text" id="fld-ath-pos" class="form-control" placeholder="e.g. Forward" required>
          </div>
        `;
      } else if (type === 'Match') {
        dynamicFields.innerHTML = `
          <div class="form-row">
            <div class="form-group col-6">
              <label class="form-label">Home Team</label>
              <select id="fld-match-home" class="form-select">
                ${State.entities.teams.map(t => `<option value="${t.name}">${t.name}</option>`).join('')}
              </select>
            </div>
            <div class="form-group col-6">
              <label class="form-label">Away Team</label>
              <select id="fld-match-away" class="form-select">
                ${State.entities.teams.map(t => `<option value="${t.name}">${t.name}</option>`).join('')}
              </select>
            </div>
          </div>
          <div class="form-group">
            <label class="form-label">Date & Time</label>
            <input type="text" id="fld-match-time" class="form-control" value="2026-11-20 19:30" required>
          </div>
          <div class="form-group">
            <label class="form-label">Venue</label>
            <input type="text" id="fld-match-venue" class="form-control" value="Titan National Arena" required>
          </div>
        `;
      }
    }

    if (btnOpenEntityModal) {
      btnOpenEntityModal.addEventListener('click', () => {
        renderDynamicFields(entityTypeSelect.value);
        UIModal.show('modal-entity');
      });
    }

    if (entityTypeSelect) {
      entityTypeSelect.addEventListener('change', (e) => renderDynamicFields(e.target.value));
    }

    const formEntity = document.getElementById('form-create-entity');
    if (formEntity) {
      formEntity.addEventListener('submit', (e) => {
        e.preventDefault();
        const type = entityTypeSelect.value;
        let data = {};

        if (type === 'Team') {
          data = {
            name: document.getElementById('fld-team-name').value,
            sport: document.getElementById('fld-team-sport').value,
            venue: document.getElementById('fld-team-venue').value,
            coach: document.getElementById('fld-team-coach').value,
            emblem: document.getElementById('fld-team-emblem').value || '🛡️',
            established: 2026,
            wins: 0,
            losses: 0
          };
        } else if (type === 'Athlete') {
          const team = document.getElementById('fld-ath-team').value;
          const matched = State.entities.teams.find(t => t.name === team);
          data = {
            name: document.getElementById('fld-ath-name').value,
            team: team,
            sport: matched ? matched.sport : 'Soccer',
            jerseyNumber: parseInt(document.getElementById('fld-ath-jersey').value, 10),
            position: document.getElementById('fld-ath-pos').value,
            healthStatus: 'Eligible',
            rating: 88
          };
        } else if (type === 'Match') {
          data = {
            homeTeam: document.getElementById('fld-match-home').value,
            awayTeam: document.getElementById('fld-match-away').value,
            sport: 'Soccer',
            dateTime: document.getElementById('fld-match-time').value,
            venue: document.getElementById('fld-match-venue').value,
            homeScore: 0,
            awayScore: 0,
            status: 'Upcoming',
            referee: 'David Sterling'
          };
        }

        EntityController.saveEntity(type, data, 'create');
        UIModal.close('modal-entity');
      });
    }

    // 24. Delete entity delegate
    document.addEventListener('click', (e) => {
      const btn = e.target.closest('.btn-delete-entity');
      if (btn) {
        const type = btn.getAttribute('data-type');
        const id = btn.getAttribute('data-id');
        if (confirm(`Delete ${type} [${id}]?`)) {
          EntityController.deleteEntity(type, id);
        }
      }
    });

    // 25. Match Scoring delegate
    document.addEventListener('click', (e) => {
      const btn = e.target.closest('.btn-score-match');
      if (btn) {
        const matchId = btn.getAttribute('data-id');
        const match = State.entities.matches.find(m => m.id === matchId);
        if (match) {
          const score = prompt(`Update Score for ${match.homeTeam} vs ${match.awayTeam} (format Home-Away):`, `${match.homeScore}-${match.awayScore}`);
          if (score && score.includes('-')) {
            const [h, a] = score.split('-').map(s => parseInt(s.trim(), 10) || 0);
            match.homeScore = h;
            match.awayScore = a;
            match.status = 'Completed';
            State.saveEntities();
            AuditLogger.log({
              action: 'MATCH_SCORE_UPDATED',
              severity: 'INFO',
              target: `Match: ${match.homeTeam} vs ${match.awayTeam}`,
              targetId: match.id,
              details: `Official score recorded: ${h} - ${a}.`
            });
            UIFeedback.toast('Score Updated', `Match [${matchId}] score updated to ${h} - ${a}.`, 'success');
            UIRenderer.renderMatches();
            UIRenderer.renderUserPortal();
          }
        }
      }
    });

    // 26. Modal close handlers
    document.querySelectorAll('.modal-close, [id^="btn-cancel"], #btn-close-view-qr').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.modal-overlay').forEach(m => m.classList.remove('active'));
        AuthController.stopPollFor2FA();
      });
    });

    document.querySelectorAll('.modal-overlay').forEach(overlay => {
      overlay.addEventListener('click', (e) => {
        if (e.target === overlay) {
          overlay.classList.remove('active');
          AuthController.stopPollFor2FA();
        }
      });
    });

    // 27. Gate Companion Tabs (QR Scanner vs On-Screen Token)
    const btnGateTabQr = document.getElementById('btn-gate-tab-qr');
    const btnGateTabSim = document.getElementById('btn-gate-tab-sim');
    const paneGateQr = document.getElementById('gate-companion-pane-qr');
    const paneGateSim = document.getElementById('gate-companion-pane-sim');

    if (btnGateTabQr && btnGateTabSim) {
      btnGateTabQr.addEventListener('click', () => {
        btnGateTabQr.classList.add('active');
        btnGateTabSim.classList.remove('active');
        if (paneGateQr) paneGateQr.style.display = 'block';
        if (paneGateSim) paneGateSim.style.display = 'none';
        QRCodeManager.updateGateQRCode();
      });

      btnGateTabSim.addEventListener('click', () => {
        btnGateTabSim.classList.add('active');
        btnGateTabQr.classList.remove('active');
        if (paneGateSim) paneGateSim.style.display = 'block';
        if (paneGateQr) paneGateQr.style.display = 'none';
      });
    }

    // 28. Gate QR Mode Switchers (Phone Camera vs Authenticator App)
    const btnGateModeWeb = document.getElementById('btn-gate-qr-mode-web');
    const btnGateModeApp = document.getElementById('btn-gate-qr-mode-app');
    if (btnGateModeWeb && btnGateModeApp) {
      btnGateModeWeb.addEventListener('click', () => {
        btnGateModeWeb.classList.add('active');
        btnGateModeApp.classList.remove('active');
        QRCodeManager.gateQrMode = 'web';
        QRCodeManager.updateGateQRCode();
      });
      btnGateModeApp.addEventListener('click', () => {
        btnGateModeApp.classList.add('active');
        btnGateModeWeb.classList.remove('active');
        QRCodeManager.gateQrMode = 'app';
        QRCodeManager.updateGateQRCode();
      });
    }

    // 29. Modal 2FA QR Mode Switchers
    const btnModalModeWeb = document.getElementById('btn-modal-qr-web');
    const btnModalModeApp = document.getElementById('btn-modal-qr-app');
    if (btnModalModeWeb && btnModalModeApp) {
      btnModalModeWeb.addEventListener('click', () => {
        btnModalModeWeb.classList.add('active');
        btnModalModeApp.classList.remove('active');
        QRCodeManager.modalQrMode = 'web';
        UIModal.updateModalQRCode();
      });
      btnModalModeApp.addEventListener('click', () => {
        btnModalModeApp.classList.add('active');
        btnModalModeWeb.classList.remove('active');
        QRCodeManager.modalQrMode = 'app';
        UIModal.updateModalQRCode();
      });
    }

    // 30. View QR Modal Mode Switchers
    const btnViewModeWeb = document.getElementById('btn-view-qr-mode-web');
    const btnViewModeApp = document.getElementById('btn-view-qr-mode-app');
    if (btnViewModeWeb && btnViewModeApp) {
      btnViewModeWeb.addEventListener('click', () => {
        btnViewModeWeb.classList.add('active');
        btnViewModeApp.classList.remove('active');
        QRCodeManager.viewQrMode = 'web';
        UIModal.updateViewQRModalCode();
      });
      btnViewModeApp.addEventListener('click', () => {
        btnViewModeApp.classList.add('active');
        btnViewModeWeb.classList.remove('active');
        QRCodeManager.viewQrMode = 'app';
        UIModal.updateViewQRModalCode();
      });
    }

    // 31. User Portal "My 2FA QR Code" Button
    const btnPortalShowQr = document.getElementById('btn-portal-show-my-qr');
    if (btnPortalShowQr) {
      btnPortalShowQr.addEventListener('click', () => {
        UIModal.showViewQRModal(State.currentUser);
      });
    }

    // 32. User Directory Table "📱 2FA QR" Click Delegate
    document.addEventListener('click', (e) => {
      const btnQr = e.target.closest('.btn-user-view-qr');
      if (btnQr) {
        const uid = btnQr.getAttribute('data-userid');
        const user = State.users.find(u => u.id === uid);
        if (user) {
          UIModal.showViewQRModal(user);
        }
      }
    });

    // 33. Seed Copy Buttons in Modals
    const btnCopySeedModal = document.getElementById('btn-copy-seed-modal');
    if (btnCopySeedModal) {
      btnCopySeedModal.addEventListener('click', () => {
        const seed = document.getElementById('modal-2fa-seed-display')?.textContent;
        if (seed) {
          navigator.clipboard.writeText(seed);
          UIFeedback.toast('Seed Copied', `Base32 secret seed copied to clipboard.`, 'success');
        }
      });
    }

    const btnCopyViewSeed = document.getElementById('btn-copy-view-qr-seed');
    if (btnCopyViewSeed) {
      btnCopyViewSeed.addEventListener('click', () => {
        const seed = document.getElementById('view-qr-seed-display')?.textContent;
        if (seed) {
          navigator.clipboard.writeText(seed);
          UIFeedback.toast('Seed Copied', `Base32 secret seed copied to clipboard.`, 'success');
        }
      });
    }

    // 34. Live Username Typing Updates Gate Companion QR
    const gateUserInp = document.getElementById('gate-username');
    if (gateUserInp) {
      gateUserInp.addEventListener('input', () => {
        const val = gateUserInp.value.trim().toLowerCase();
        const found = State.users.find(u => u.username.toLowerCase() === val);
        if (found) {
          QRCodeManager.updateGateQRCode(found);
        }
      });
    }

    // 35. Cross-tab LocalStorage Push Listener (for multi-tab testing)
    window.addEventListener('storage', (e) => {
      if (e.key === 'titan_mobile_push_event' && e.newValue) {
        try {
          const pushData = JSON.parse(e.newValue);
          const modalActive = document.getElementById('modal-2fa')?.classList.contains('active');
          if (modalActive && pushData && pushData.code) {
            const otpInput = document.getElementById('input-2fa-otp');
            if (otpInput) otpInput.value = pushData.code;

            const alertEl = document.getElementById('modal-code-received-alert');
            if (alertEl) alertEl.style.display = 'flex';

            const relayStatus = document.getElementById('modal-relay-status');
            if (relayStatus) {
              relayStatus.className = 'relay-status-pill';
              relayStatus.innerHTML = '<span class="pulse-dot"></span> <span>Code received from mobile phone!</span>';
            }

            UIFeedback.toast('Device Synchronized', `6-digit token [${pushData.code}] received from your device!`, 'success');

            setTimeout(() => {
              AuthController.verify2FA(pushData.code);
            }, 600);
          }
        } catch (err) {}
      }
    });
  }

  /* ===========================================================================
     SECTION 15: BOOTSTRAPPER & INITIALIZATION
     =========================================================================== */

  async function bootstrap() {
    console.log("⚡ [TITAN SPORTS OS] Initializing Light Enterprise System & 2FA QR Relay...");

    // 1. Initialize persistent state
    State.init();

    // 2. Initialize QR Code network detection
    await QRCodeManager.init();

    // 3. Start TOTP rotation clock and Gate Companion
    AuthenticatorSimulator.init();

    // 4. Setup event listeners
    setupEventListeners();

    // 5. Check initial view state: Gate Screen vs Authenticated Platform
    const gateScreen = document.getElementById('auth-gate-screen');
    const mainApp = document.getElementById('app-authenticated-container');

    if (State.isAuthenticated && State.currentUser) {
      if (gateScreen) gateScreen.style.display = 'none';
      if (mainApp) mainApp.style.display = 'block';
      UIRenderer.renderAll();
    } else {
      if (gateScreen) gateScreen.style.display = 'flex';
      if (mainApp) mainApp.style.display = 'none';
    }

    // 6. Initial audit log if empty
    if (State.auditLogs.length === 0) {
      AuditLogger.log({
        action: 'SYSTEM_BOOT',
        severity: 'INFO',
        target: 'System Core',
        details: 'Titan Sports OS core security online. Light theme active, 2FA enabled, RBAC initialized.'
      });
    }

    console.log("⚡ [TITAN SPORTS OS] System Ready.");
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', bootstrap);
  } else {
    bootstrap();
  }

})();
