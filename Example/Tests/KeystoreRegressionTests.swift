import XCTest
@testable import TLCore

class KeystoreRegressionTests: XCTestCase {
    /// BIP39 test vector.
    private let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    private let password = "keystore-password"

    private var keyDirectory: URL!
    private var shouldRemoveKeyDirectory = true

    override func setUp() {
        super.setUp()
        keyDirectory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        shouldRemoveKeyDirectory = true
    }

    override func tearDown() {
        if shouldRemoveKeyDirectory {
            try? FileManager.default.removeItem(at: keyDirectory)
        }
        super.tearDown()
    }

    /// The passphrase is a BIP39 derivation input, so losing it across a restart silently
    /// re-derives a different private key for the same address.
    func testPassphraseSurvivesReload() throws {
        let passphrase = "correct horse battery staple"

        let store = try KeyStore(keyDirectory: keyDirectory)
        _ = try store.import(mnemonic: mnemonic, passphrase: passphrase, encryptPassword: password)

        let reloaded = try KeyStore(keyDirectory: keyDirectory)
        let account = try XCTUnwrap(reloaded.accounts.first)
        let exported = try reloaded.exportPrivateKey(account: account, password: password)

        let expected = try Wallet(mnemonic: mnemonic, passphrase: passphrase).getKey(at: 0).privateKey
        XCTAssertEqual(exported, expected)
    }

    /// An empty passphrase must keep producing the pre-existing payload layout, otherwise keys
    /// written by earlier versions no longer decode.
    func testKeyWithoutPassphraseSurvivesReload() throws {
        let store = try KeyStore(keyDirectory: keyDirectory)
        _ = try store.import(mnemonic: mnemonic, encryptPassword: password)

        let reloaded = try KeyStore(keyDirectory: keyDirectory)
        let account = try XCTUnwrap(reloaded.accounts.first)
        XCTAssertEqual(try reloaded.exportMnemonic(account: account, password: password), mnemonic)

        let expected = try Wallet(mnemonic: mnemonic).getKey(at: 0).privateKey
        XCTAssertEqual(try reloaded.exportPrivateKey(account: account, password: password), expected)
    }

    /// Guards the round trip against a payload split that would hand the passphrase bytes back
    /// as part of the mnemonic.
    func testExportedMnemonicExcludesPassphrase() throws {
        let store = try KeyStore(keyDirectory: keyDirectory)
        let account = try store.import(mnemonic: mnemonic, passphrase: "p@ss", encryptPassword: password)
        XCTAssertEqual(try store.exportMnemonic(account: account, password: password), mnemonic)
    }

    func testHDObjectsDoNotRetainMnemonicOrPassphrase() throws {
        let passphrase = "p@ss"
        let wallet = try Wallet(mnemonic: mnemonic, passphrase: passphrase)
        let walletFields = Mirror(reflecting: wallet).children.compactMap { $0.label }
        let walletStrings = Mirror(reflecting: wallet).children.compactMap { $0.value as? String }
        XCTAssertFalse(walletFields.contains("mnemonic"))
        XCTAssertFalse(walletFields.contains("passphrase"))
        XCTAssertFalse(walletStrings.contains(mnemonic))
        XCTAssertFalse(walletStrings.contains(passphrase))

        let key = try KeystoreKey(password: password, mnemonic: mnemonic, passphrase: passphrase)
        let keyFields = Mirror(reflecting: key).children.compactMap { $0.label }
        let keyStrings = Mirror(reflecting: key).children.compactMap { $0.value as? String }
        XCTAssertFalse(keyFields.contains("mnemonic"))
        XCTAssertFalse(keyFields.contains("passphrase"))
        XCTAssertFalse(keyStrings.contains(mnemonic))
        XCTAssertFalse(keyStrings.contains(passphrase))

        let store = try KeyStore(keyDirectory: keyDirectory)
        let account = try store.import(mnemonic: mnemonic, passphrase: passphrase, encryptPassword: password)
        let cachedKey = try XCTUnwrap(store.key(for: account.address))
        let cachedStrings = Mirror(reflecting: cachedKey).children.compactMap { $0.value as? String }
        XCTAssertFalse(cachedStrings.contains(mnemonic))
        XCTAssertFalse(cachedStrings.contains(passphrase))

        wallet.clear()
        XCTAssertThrowsError(try wallet.getKey(at: 0)) { error in
            guard case Wallet.Error.cleared = error else {
                return XCTFail("Unexpected error: \(error)")
            }
        }
        XCTAssertEqual(try store.exportMnemonic(account: account, password: password), mnemonic)
    }

    func testGeneratedHDWalletReturnsMnemonicWithoutRetainingIt() throws {
        let generated = try KeystoreKey.generateHDWallet(password: password)
        XCTAssertTrue(Mnemonic.isValid(generated.mnemonic))
        XCTAssertEqual(try KeystoreKey(password: password, mnemonic: generated.mnemonic).address,
                       generated.key.address)
        XCTAssertFalse(Mirror(reflecting: generated.key).children.compactMap { $0.label }.contains("mnemonic"))

        let store = try KeyStore(keyDirectory: keyDirectory)
        let account = try store.createAccount(password: password, type: .hierarchicalDeterministicWallet)
        XCTAssertTrue(Mnemonic.isValid(try store.exportMnemonic(account: account, password: password)))
    }

    func testDeleteRequiresCorrectPassword() throws {
        let store = try KeyStore(keyDirectory: keyDirectory)
        let account = try store.import(mnemonic: mnemonic, encryptPassword: password)

        XCTAssertThrowsError(try store.delete(account: account, password: "wrong-password")) { error in
            guard case DecryptError.invalidPassword = error else {
                return XCTFail("Expected invalidPassword, got \(error)")
            }
        }
        XCTAssertNotNil(store.account(for: account.address))
        XCTAssertNotNil(store.key(for: account.address))
        XCTAssertTrue(FileManager.default.fileExists(atPath: account.url.path))

        let unrelatedURL = keyDirectory.appendingPathComponent("unrelated")
        try Data().write(to: unrelatedURL)
        var suppliedAccount = account
        suppliedAccount.url = unrelatedURL

        try store.delete(account: suppliedAccount, password: password)
        XCTAssertNil(store.account(for: account.address))
        XCTAssertNil(store.key(for: account.address))
        XCTAssertFalse(FileManager.default.fileExists(atPath: account.url.path))
        XCTAssertTrue(FileManager.default.fileExists(atPath: unrelatedURL.path))
    }

    func testDifferentPassphrasesDeriveDifferentKeys() throws {
        let a = try Wallet(mnemonic: mnemonic, passphrase: "one").getKey(at: 0).privateKey
        let b = try Wallet(mnemonic: mnemonic, passphrase: "two").getKey(at: 0).privateKey
        XCTAssertNotEqual(a, b)
    }

    /// The C layer bounds the passphrase in bytes. Checking `String.count` let a multi-byte
    /// passphrase past the guard and turned the derivation failure into a trap.
    func testOverlongMultiBytePassphraseThrows() {
        let passphrase = String(repeating: "🔑", count: 65) // 65 characters, 260 UTF-8 bytes
        XCTAssertEqual(passphrase.count, 65)
        XCTAssertEqual(passphrase.utf8.count, 260)
        XCTAssertThrowsError(try Mnemonic.deriveSeed(mnemonic: mnemonic, passphrase: passphrase))
    }

    /// A 256-byte passphrase is exactly at the limit and must still derive.
    func testPassphraseAtByteLimitDerives() throws {
        let passphrase = String(repeating: "a", count: 256)
        XCTAssertEqual(try Mnemonic.deriveSeed(mnemonic: mnemonic, passphrase: passphrase).count, 64)
    }

    /// `EthereumCrypto` reports an invalid private key by returning an empty `Data`, since its
    /// return type is `nonnull`. Decoding an address from that used to trap, including in release
    /// builds, rather than surfacing an error.
    func testInvalidPrivateKeyThrowsInsteadOfTrapping() {
        XCTAssertThrowsError(try KeystoreKey(password: password, key: Data(repeating: 1, count: 16)))
        XCTAssertThrowsError(try KeystoreKey(password: password, key: Data(repeating: 0, count: 32)))
    }

    /// `import(json:)` used to send every decrypted payload through the raw-key path. For an HD
    /// keystore that made the private key the first 32 characters of the mnemonic.
    func testHDKeystoreJSONRoundTripPreservesAddress() throws {
        let store = try KeyStore(keyDirectory: keyDirectory)
        let account = try store.import(mnemonic: mnemonic, passphrase: "p@ss", encryptPassword: password)
        let json = try store.export(account: account, password: password, newPassword: password)

        let target = try KeyStore(keyDirectory: keyDirectory.appendingPathComponent("imported"))
        let imported = try target.import(json: json, password: password, newPassword: password)

        XCTAssertEqual(imported.address, account.address)
        XCTAssertEqual(imported.type, .hierarchicalDeterministicWallet)
        XCTAssertEqual(try target.exportMnemonic(account: imported, password: password), mnemonic)
        XCTAssertEqual(try target.exportPrivateKey(account: imported, password: password),
                       try store.exportPrivateKey(account: account, password: password))
    }

    func testUpdatePasswordPreservesCustomDerivationPathAndRejectsAddressChange() throws {
        let customPath = "m/44'/195'/7'/0/3"
        let importingStore = try KeyStore(keyDirectory: keyDirectory)
        let account = try importingStore.import(mnemonic: mnemonic, derivationPath: customPath, encryptPassword: password)
        let privateKey = try importingStore.exportPrivateKey(account: account, password: password)

        let store = try KeyStore(keyDirectory: keyDirectory)
        let storedAccount = try XCTUnwrap(store.account(for: account.address))

        XCTAssertThrowsError(try store.update(account: storedAccount,
                                              password: password,
                                              newPassword: "wrong-path-password",
                                              derivationPath: Wallet.defaultPath)) { error in
            guard case KeyStore.Error.invalidKey = error else {
                return XCTFail("expected invalidKey, got \(error)")
            }
        }

        let unchangedStore = try KeyStore(keyDirectory: keyDirectory)
        let unchangedAccount = try XCTUnwrap(unchangedStore.account(for: account.address))
        XCTAssertEqual(try unchangedStore.generateWalletPath(account: unchangedAccount), customPath)
        XCTAssertEqual(try unchangedStore.exportPrivateKey(account: unchangedAccount, password: password), privateKey)

        let updatedPassword = "updated-keystore-password"
        try unchangedStore.update(account: unchangedAccount, password: password, newPassword: updatedPassword)

        let reloaded = try KeyStore(keyDirectory: keyDirectory)
        let reloadedAccount = try XCTUnwrap(reloaded.account(for: account.address))
        XCTAssertEqual(try reloaded.generateWalletPath(account: reloadedAccount), customPath)
        XCTAssertEqual(try reloaded.exportPrivateKey(account: reloadedAccount, password: updatedPassword), privateKey)
    }

    func testLegacyOversizedEncryptedKeyUsesFirst32BytesAcrossKeyStoreAPIs() throws {
        let legacy = try makeLegacyOversizedEncryptedKey()
        XCTAssertGreaterThan(try legacy.key.decrypt(password: password).count, legacy.privateKey.count)

        let store = try KeyStore(keyDirectory: keyDirectory)
        let account = Account(address: legacy.key.address,
                              type: .encryptedKey,
                              url: keyDirectory.appendingPathComponent("legacy-oversized.json"))
        try store.addKey(key: legacy.key)
        try store.addAccount(account: account)

        XCTAssertEqual(try store.exportPrivateKey(account: account, password: password), legacy.privateKey)

        let exported = try store.export(account: account, password: password, newPassword: password)
        let exportedKey = try JSONDecoder().decode(KeystoreKey.self, from: exported)
        XCTAssertEqual(exportedKey.type, .encryptedKey)
        XCTAssertEqual(try exportedKey.decrypt(password: password), legacy.privateKey)

        let updatedPassword = "updated-keystore-password"
        try store.update(account: account, password: password, newPassword: updatedPassword)
        XCTAssertEqual(try store.exportPrivateKey(account: account, password: updatedPassword), legacy.privateKey)

        let target = try KeyStore(keyDirectory: keyDirectory.appendingPathComponent("legacy-imported"))
        let imported = try target.import(json: legacy.json, password: password, newPassword: updatedPassword)
        XCTAssertEqual(imported.address, legacy.key.address)
        XCTAssertEqual(try target.exportPrivateKey(account: imported, password: updatedPassword), legacy.privateKey)
    }

    /// A keystore whose declared address disagrees with the decrypted secret is tampered with.
    func testImportRejectsAddressMismatch() throws {
        let store = try KeyStore(keyDirectory: keyDirectory)
        let account = try store.import(mnemonic: mnemonic, encryptPassword: password)
        let json = try store.export(account: account, password: password, newPassword: password)

        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: json, options: []) as? [String: Any])
        object["address"] = String(repeating: "1", count: 42)
        let tampered = try JSONSerialization.data(withJSONObject: object, options: [])

        let target = try KeyStore(keyDirectory: keyDirectory.appendingPathComponent("tampered"))
        XCTAssertThrowsError(try target.import(json: tampered, password: password, newPassword: password)) { error in
            switch error as? KeyStore.Error {
            case .invalidKey: break
            default: XCTFail("expected invalidKey, got \(error)")
            }
        }
    }

    /// Mnemonic bytes must never be accepted as a raw secp256k1 scalar, at any length.
    func testKeystoreKeyRejectsMnemonicASCIIPayload() throws {
        let payload = try XCTUnwrap(mnemonic.data(using: .ascii))
        assertRejectsPrivateKey(payload)
        assertRejectsPrivateKey(payload.prefix(32))
    }

    /// 32 bytes of printable ASCII form a valid scalar, so only the guard rejects them.
    func testKeystoreKeyRejectsAllPrintableASCIIInput() {
        assertRejectsPrivateKey(Data(repeating: 0x41, count: 32))
    }

    /// The guard must not reject legitimate keys.
    func testKeystoreKeyAcceptsValid32BytePrivateKey() throws {
        let privateKey = try Wallet(mnemonic: mnemonic).getKey(at: 0).privateKey
        XCTAssertEqual(privateKey.count, 32)
        XCTAssertEqual(try KeystoreKey(password: password, key: privateKey).type, .encryptedKey)
    }

    func testConcurrentImportStoresOneAccount() throws {
        let password = self.password
        let key = try KeystoreKey(password: password, mnemonic: mnemonic)
        let json = try JSONEncoder().encode(key)
        let store = try KeyStore(keyDirectory: keyDirectory)
        let queue = DispatchQueue(label: "org.tronlink.keystore.concurrent-import", attributes: .concurrent)
        let start = DispatchSemaphore(value: 0)
        let ready = DispatchGroup()
        let group = DispatchGroup()
        let resultLock = NSLock()
        var successCount = 0
        var duplicateCount = 0
        var unexpectedErrors = [Swift.Error]()

        for _ in 0..<2 {
            ready.enter()
            group.enter()
            queue.async {
                ready.leave()
                start.wait()
                defer { group.leave() }
                do {
                    _ = try store.import(json: json, password: password, newPassword: password)
                    resultLock.lock()
                    successCount += 1
                    resultLock.unlock()
                } catch KeyStore.Error.accountAlreadyExists {
                    resultLock.lock()
                    duplicateCount += 1
                    resultLock.unlock()
                } catch {
                    resultLock.lock()
                    unexpectedErrors.append(error)
                    resultLock.unlock()
                }
            }
        }

        guard ready.wait(timeout: .now() + 5) == .success else {
            start.signal()
            start.signal()
            if group.wait(timeout: .now() + 60) != .success {
                shouldRemoveKeyDirectory = false
            }
            XCTFail("concurrent import workers failed to start")
            return
        }
        start.signal()
        start.signal()
        guard group.wait(timeout: .now() + 60) == .success else {
            // ponytail: synchronous import cannot be cancelled; use a subprocess if timeout cleanup becomes necessary.
            shouldRemoveKeyDirectory = false
            XCTFail("concurrent imports timed out")
            return
        }

        XCTAssertEqual(successCount, 1)
        XCTAssertEqual(duplicateCount, 1)
        XCTAssertTrue(unexpectedErrors.isEmpty, "unexpected errors: \(unexpectedErrors)")
        XCTAssertEqual(store.accounts.count, 1)
        let account = try XCTUnwrap(store.accounts.first)
        XCTAssertNotNil(store.key(for: account.address))
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(at: keyDirectory, includingPropertiesForKeys: []).count, 1)
        XCTAssertEqual(try KeyStore(keyDirectory: keyDirectory).accounts.count, 1)
    }

    // MARK: - TL-KDF-002: scrypt parameters arriving from untrusted keystore JSON

    /// Every preset the app has ever written to disk, plus the desktop preset users import
    /// from, must keep validating. A regression here bricks existing wallets rather than
    /// merely rejecting an import, so this is the guard rail on the new upper bounds.
    func testValidateAcceptsShippedAndStandardPresets() {
        let salt = Data(repeating: 0xAB, count: 32)
        let presets: [(String, Int, Int, Int)] = [
            ("light — what 1.0.4 wrote on disk", ScryptParams.lightN, ScryptParams.defaultR, ScryptParams.lightP),
            ("balanced — current default", ScryptParams.balancedN, ScryptParams.defaultR, ScryptParams.balancedP),
            ("go-ethereum standard — imported from desktop", ScryptParams.standardN, ScryptParams.defaultR, ScryptParams.standardP),
            // The memory ceiling itself: 128 * 8 * 2^19 == 512 MiB exactly. Pinning the
            // boundary from the accepting side catches an off-by-one that would silently
            // start rejecting the strongest configuration we intend to support.
            ("largest n the memory cap admits at r = 8", 1 << 19, ScryptParams.defaultR, 1),
        ]
        for (label, n, r, p) in presets {
            XCTAssertNoThrow(
                try ScryptParams(salt: salt, n: n, r: r, p: p, desiredKeyLength: ScryptParams.defaultDesiredKeyLength),
                "\(label) must remain valid"
            )
        }
    }

    /// The `r` / `p` / `dklen` ceilings deliberately match Android's
    /// `org.tron.net.KeyStoreUtils`, which rejects `r` outside 1...64, `p` outside 1...16
    /// and `dklen` outside 32...1024. A keystore is a file users carry between the two
    /// apps, so a file accepted on one must be accepted on the other.
    func testValidateMatchesAndroidBoundsForRPAndDklen() {
        let salt = Data(repeating: 0xAB, count: 32)

        // Exactly Android's ceilings — must be accepted.
        XCTAssertNoThrow(try ScryptParams(salt: salt, n: 4096, r: 64, p: 1, desiredKeyLength: 32))
        XCTAssertNoThrow(try ScryptParams(salt: salt, n: 4096, r: 8, p: 16, desiredKeyLength: 32))
        XCTAssertNoThrow(try ScryptParams(salt: salt, n: 4096, r: 8, p: 1, desiredKeyLength: 1024))

        // One past each — must be refused on both clients.
        XCTAssertThrowsError(try ScryptParams(salt: salt, n: 4096, r: 65, p: 1, desiredKeyLength: 32))
        XCTAssertThrowsError(try ScryptParams(salt: salt, n: 4096, r: 8, p: 17, desiredKeyLength: 32))
        XCTAssertThrowsError(try ScryptParams(salt: salt, n: 4096, r: 8, p: 1, desiredKeyLength: 1025))

        // At r = 1 the memory rule alone would allow 2^22, which Android rejects. The flat
        // `maxN` ceiling keeps the two clients from diverging in that direction too.
        XCTAssertNoThrow(try ScryptParams(salt: salt, n: 1 << 20, r: 1, p: 1, desiredKeyLength: 32))
        XCTAssertThrowsError(try ScryptParams(salt: salt, n: 1 << 21, r: 1, p: 1, desiredKeyLength: 32))
        XCTAssertThrowsError(try ScryptParams(salt: salt, n: 1 << 22, r: 1, p: 1, desiredKeyLength: 32))
    }

    /// Android refuses a keystore carrying no scrypt salt, and so must we: deriving from
    /// an empty salt makes the KDF output depend on the password alone.
    func testValidateRejectsEmptySalt() {
        XCTAssertThrowsError(
            try ScryptParams(salt: Data(), n: 4096, r: 8, p: 1, desiredKeyLength: 32)
        ) { error in
            guard let validationError = error as? ScryptParams.ValidationError,
                  case .emptySalt = validationError else {
                XCTFail("Expected emptySalt, got \(error)")
                return
            }
        }
    }

    /// Hostile values must be *rejected*, not trapped.
    ///
    /// Before TL-KDF-002 the negative and zero cases below crashed inside `validate()`
    /// itself — `UInt64(-1)` on the block-size line, and division by `p`/`r` on the
    /// overflow line — so this test would have taken the whole runner down instead of
    /// failing. `dklen = 0` and the oversized `n` values were accepted outright and blew
    /// up further downstream, in `decrypt`'s slicing and in the scrypt allocator.
    func testValidateRejectsHostileParametersWithoutTrapping() {
        let salt = Data(repeating: 0xAB, count: 32)
        let hostile: [(String, Int, Int, Int, Int)] = [
            ("negative r", 4096, -1, 1, 32),
            ("zero r", 4096, 0, 1, 32),
            ("zero p", 4096, 8, 0, 32),
            ("negative p", 4096, 8, -1, 32),
            ("zero n", 0, 8, 1, 32),
            ("negative n", -4096, 8, 1, 32),
            ("n not a power of two", 4097, 8, 1, 32),
            ("n one step past the memory cap", 1 << 20, 8, 1, 32),
            ("n = 2^40", 1 << 40, 8, 1, 32),
            ("dklen 0", 4096, 8, 1, 0),
            ("dklen 16 — decrypt's two slices would overlap", 4096, 8, 1, 16),
            ("negative dklen", 4096, 8, 1, -1),
            ("dklen Int.max", 4096, 8, 1, Int.max),
            ("dklen past its cap", 4096, 8, 1, 1025),
            ("r past its cap", 4096, 65, 1, 32),
            ("p past its cap", 4096, 8, 17, 32),
        ]
        for (label, n, r, p, dklen) in hostile {
            XCTAssertThrowsError(
                try ScryptParams(salt: salt, n: n, r: r, p: p, desiredKeyLength: dklen),
                "\(label) must be rejected"
            ) { error in
                XCTAssertTrue(
                    error is ScryptParams.ValidationError,
                    "\(label) must fail with a typed ValidationError, got \(error)"
                )
            }
        }
    }

    /// Backward compatibility, end to end. The light preset is what every install predating
    /// TL-KDF-001 has sitting on disk, so the new bounds must let those files through.
    /// Loading never decrypts — `KeystoreKey(contentsOf:)` only decodes — so the bounds are
    /// first reached at unlock time, and this asserts scrypt actually runs to completion there.
    func testLegacyLightPresetStillDerivesUnderNewBounds() throws {
        let params = try ScryptParams(salt: Data(repeating: 0xAB, count: 32),
                                      n: ScryptParams.lightN,
                                      r: ScryptParams.defaultR,
                                      p: ScryptParams.lightP,
                                      desiredKeyLength: ScryptParams.defaultDesiredKeyLength)
        XCTAssertNil(params.validate())
        XCTAssertEqual(try Scrypt(params: params).calculate(password: password).count, 32)

        // And through the file path: a light-preset keystore must fail on its deliberately
        // junk MAC, never on parameter validation — that is what proves it got through.
        let json = makeKeystoreJSON(n: ScryptParams.lightN,
                                    r: ScryptParams.defaultR,
                                    p: ScryptParams.lightP,
                                    dklen: ScryptParams.defaultDesiredKeyLength)
        let key = try JSONDecoder().decode(KeystoreKey.self, from: json)
        XCTAssertThrowsError(try key.decrypt(password: password)) { error in
            XCTAssertFalse(error is ScryptParams.ValidationError,
                           "The light preset must not be rejected by the new bounds, got \(error)")
        }
    }

    /// The actual attack path, end to end: a keystore file carrying hostile kdfparams.
    ///
    /// Decoding must stay permissive — `KeyStore.load()` silently skips files it cannot
    /// decode, so tightening `init(from:)` would make a wallet vanish from the list with
    /// no error at all. The rejection belongs at decryption time, where it surfaces as a
    /// catchable error.
    func testHostileKDFParamsDecodeButFailToDecrypt() throws {
        let hostile: [(String, Int, Int, Int, Int)] = [
            ("negative r", 4096, -1, 1, 32),
            ("zero p", 4096, 8, 0, 32),
            ("dklen 0", 4096, 8, 1, 0),
            ("n = 2^40", 1 << 40, 8, 1, 32),
        ]
        for (label, n, r, p, dklen) in hostile {
            let json = makeKeystoreJSON(n: n, r: r, p: p, dklen: dklen)
            let key = try JSONDecoder().decode(KeystoreKey.self, from: json)
            XCTAssertEqual(key.crypto.kdfParams.n, n, "\(label): decoding must stay permissive")
            XCTAssertThrowsError(
                try key.decrypt(password: password),
                "\(label) must throw rather than trap or exhaust memory"
            )
        }
    }

    /// Builds a syntactically valid V3 keystore carrying arbitrary kdfparams. The MAC is
    /// junk on purpose: these files must be rejected on their parameters, long before any
    /// password check could matter.
    private func makeKeystoreJSON(n: Int, r: Int, p: Int, dklen: Int) -> Data {
        let json: [String: Any] = [
            "address": "410000000000000000000000000000000000000000",
            "type": "private-key",
            "id": UUID().uuidString.lowercased(),
            "version": 3,
            "crypto": [
                "ciphertext": String(repeating: "00", count: 32),
                "cipher": "aes-128-ctr",
                "cipherparams": ["iv": String(repeating: "00", count: 16)],
                "kdf": "scrypt",
                "kdfparams": [
                    "salt": String(repeating: "00", count: 32),
                    "dklen": dklen,
                    "n": n,
                    "p": p,
                    "r": r,
                ],
                "mac": String(repeating: "00", count: 32),
            ],
        ]
        // Force-try is fine here: the literal above is always serializable.
        return try! JSONSerialization.data(withJSONObject: json)
    }

    private func makeLegacyOversizedEncryptedKey() throws -> (key: KeystoreKey, privateKey: Data, json: Data) {
        let privateKey = try Wallet(mnemonic: mnemonic).getKey(at: 0).privateKey
        var payload = privateKey
        payload.append(contentsOf: Array(" legacy oversized encrypted-key payload".utf8))

        var key = try KeystoreKey(password: password, key: privateKey)
        key.crypto = try KeystoreKeyHeader(password: password, data: payload)
        key.type = .encryptedKey
        return (key, privateKey, try JSONEncoder().encode(key))
    }

    private func assertRejectsPrivateKey(_ key: Data, file: StaticString = #file, line: UInt = #line) {
        XCTAssertThrowsError(try KeystoreKey(password: password, key: key), file: file, line: line) { error in
            switch error as? EncryptError {
            case .invalidPrivateKey: break
            default: XCTFail("expected invalidPrivateKey, got \(error)", file: file, line: line)
            }
        }
    }
}
