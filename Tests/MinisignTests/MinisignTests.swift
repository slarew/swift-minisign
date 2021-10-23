// SPDX-License-Identifier: MIT
// Copyright 2021 Stephen Larew

import XCTest
import Minisign

final class MinisignTests: XCTestCase {

  // password: test
  static let privKey = """
    untrusted comment: minisign encrypted secret key
    RWRTY0Iyvmea6pdrXYdDVqn91GknFBllkJmsQyS2jpVGoBqETB4AAAACAAAAAAAAAEAAAAAAr5jLDlb+ahHMPoPZAawLCKbUilW5ECEFsFCFSQLXfKrFQDv54sYqJzr3rR4gTmDnplQY+/T+EYCZkc5+QJOWwmaKBHPRx+Tw3rFH4CfCGkYRr4WNdZprmAzi1ZNzTl/wyvc1/uplgO8=

    """

  static let pubKey = """
    untrusted comment: minisign public key E28A983382D6D7E9
    RWTp19aCM5iK4plw14gbtviwUSISZP++TJMfOfNTKoCcRIkcrV13Oppe
    
    """

  static let signature = """
    untrusted comment: signature from minisign secret key
    RWTp19aCM5iK4olS02BlgllVHi3lvR9OYUVu7gM/lMsTRsO2Qb1IBxJBt3xW14hAFZo7Zlceavr7u69Rt0Wk5wMX0ShF13DZygY=
    trusted comment: timestamp:1629695994\tfile:test.pub
    o4E++I6KyX1h3iYMQ5yNyqEfhphdrIXiFmnWarzbB1BQpsckcO1I3LLttzS1w2CjCEauKZ3bOeY//sYui8rbAQ==

    """

  static let badSignature = """
    untrusted comment: signature from minisign secret key
    RWTp19aCM5iK4olS02BlgllVHi3lvR9OYUVu7gM/lMsTRsO2Qb1IBxJBt3xW14hAFZo7Zlceavr7u69Rt0Wk5wMX0ShF13DZygY=
    trusted comment: timestamp:1629695994\tfile:test.pu
    o4E++I6KyX1h3iYMQ5yNyqEfhphdrIXiFmnWarzbB1BQpsckcO1I3LLttzS1w2CjCEauKZ3bOeY//sYui8rbAQ==

    """

  static let prehashedSignature = """
    untrusted comment: signature from minisign secret key
    RUTp19aCM5iK4qzCz7Z/Y4YGsKxamuPediRB9WhvHRWnrJFREb/m9TCwxQUlug1QMYMqgaEi3IGS0trOxy4xhCkS3D7ksjLEFQg=
    trusted comment: timestamp:1629695918\tfile:test.pub
    0sZUtAIqxCkdV8nQ5+bODUIX09QZS4ilrsCT6wjkTXhsMJ2cQKL0wYH3Km8ZGG46Q2OhOY8sPl+2DTLjvrMmBg==

    """

  static let badPrehashedSignature = """
    untrusted comment: signature from minisign secret key
    RUTp19aCM5iK4qzCz7Z/Y4YGsKxamuPediRB9WhvHRWnrJFREb/m9TCwxQUlug1QMYMqgaEi3IGS0trOxy4xhCkS3D7ksjLEFQg=
    trusted comment: timestamp:1629695918\tfile:test.pu
    0sZUtAIqxCkdV8nQ5+bODUIX09QZS4ilrsCT6wjkTXhsMJ2cQKL0wYH3Km8ZGG46Q2OhOY8sPl+2DTLjvrMmBg==

    """


  func testParse() {
    let pubKey = PubKey(text: Self.pubKey.data(using: .utf8)!)
    XCTAssertNotNil(pubKey)
    XCTAssertEqual(pubKey?.untrustedComment, "minisign public key E28A983382D6D7E9")
    XCTAssertEqual(pubKey?.keyID, Data(base64Encoded: "6dfWgjOYiuI=")!)
    XCTAssertEqual(pubKey?.signatureAlgorithm, .pureEdDSA)
    let sig = Signature(text: Self.signature.data(using: .utf8)!)
    XCTAssertNotNil(sig)
    XCTAssertEqual(sig?.untrustedComment, "signature from minisign secret key")
    XCTAssertEqual(sig?.trustedComment, "timestamp:1629695994\tfile:test.pub")
    XCTAssertEqual(sig?.signatureAlgorithm, .pureEdDSA)
    XCTAssertEqual(sig?.keyID, Data(base64Encoded: "6dfWgjOYiuI=")!)
  }

  func testSignature() {
    let pubKey = PubKey(text: Self.pubKey.data(using: .utf8)!)
    XCTAssertNotNil(pubKey)
    let sig = Signature(text: Self.signature.data(using: .utf8)!)
    XCTAssertNotNil(sig)

    XCTAssert(pubKey!.isValidSignature(sig!, for: Self.pubKey.data(using: .utf8)!))
    XCTAssertFalse(pubKey!.isValidSignature(sig!, for: Self.pubKey.data(using: .utf8)!.advanced(by: 1)))

    let badSig = Signature(text: Self.badSignature.data(using: .utf8)!)
    XCTAssertNotNil(badSig)
    XCTAssertFalse(pubKey!.isValidSignature(badSig!, for: Self.pubKey.data(using: .utf8)!))
  }

  func testPrehashedSignature() {
    let pubKey = PubKey(text: Self.pubKey.data(using: .utf8)!)
    XCTAssertNotNil(pubKey)
    let phSig = Signature(text: Self.prehashedSignature.data(using: .utf8)!)
    XCTAssertNotNil(phSig)

    XCTAssert(pubKey!.isValidSignature(phSig!, for: Self.pubKey.data(using: .utf8)!))
    XCTAssertFalse(pubKey!.isValidSignature(phSig!, for: Self.pubKey.data(using: .utf8)!.advanced(by: 1)))

    let badPhSig = Signature(text: Self.badPrehashedSignature.data(using: .utf8)!)
    XCTAssertNotNil(badPhSig)
    XCTAssertFalse(pubKey!.isValidSignature(badPhSig!, for: Self.pubKey.data(using: .utf8)!))
  }

}

