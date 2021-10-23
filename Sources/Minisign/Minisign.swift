// SPDX-License-Identifier: MIT
// Copyright 2021 Stephen Larew

import Foundation
import Crypto
import BLAKE2

public enum SignatureAlgorithm: RawRepresentable {
  case pureEdDSA
  case hashedEdDSA

  private static let dataEd = "Ed".data(using: .utf8)!
  private static let dataED = "ED".data(using: .utf8)!

  public init?(rawValue: Data) {
    if rawValue == Self.dataEd {
      self = .pureEdDSA
    } else if rawValue == Self.dataED {
      self = .hashedEdDSA
    } else {
      return nil
    }
  }

  public var rawValue: Data {
    switch self {
    case .pureEdDSA: return Self.dataEd
    case .hashedEdDSA: return Self.dataED
    }
  }
}

private let untrustedCommentHeader = "untrusted comment: ".data(using: .utf8)!
private let trustedCommentHeader = "trusted comment: ".data(using: .utf8)!

public struct PubKey {
  public let untrustedComment: String
  public let signatureAlgorithm: SignatureAlgorithm
  public let keyID: Data
  public let publicKey: Curve25519.Signing.PublicKey

  public init?<D>(text: D) where D : DataProtocol {
    let lines = text.split(separator: UInt8(ascii: "\n"), maxSplits: 2, omittingEmptySubsequences: false)
    guard lines.count == 2 || lines[2].isEmpty else { return nil }
    guard lines[0].starts(with: untrustedCommentHeader ) else { return nil }
    guard let untrustedComment = String(data: Data(lines[0].suffix(from: untrustedCommentHeader.count as! D.Index)), encoding: .utf8) else { return nil }
    self.untrustedComment = untrustedComment
    guard let decLine2 = Data(base64Encoded: Data(lines[1]), options: []) else { return nil }
    guard decLine2.count == 42 else { return nil }
    guard let sigAlgo = SignatureAlgorithm(rawValue: decLine2.prefix(2)),
          sigAlgo == .pureEdDSA
    else { return nil }
    self.signatureAlgorithm = sigAlgo
    self.keyID = decLine2[2..<10]
    guard let publicKey = try? Curve25519.Signing.PublicKey(rawRepresentation: decLine2[10..<42]) else {
      return nil
    }
    self.publicKey = publicKey
  }

  public func isValidSignature<D>(_ signature: Signature, for data: D) -> Bool where D: DataProtocol {
    guard signature.keyID == keyID else { return false }
    switch signature.signatureAlgorithm {
    case .pureEdDSA:
      guard publicKey.isValidSignature(signature.signature, for: data) else { return false }
    case .hashedEdDSA:
      let digest = BLAKE2b.hash(data: data)
      guard digest.withUnsafeBytes({
        publicKey.isValidSignature(signature.signature, for: $0)
      }) else {
        return false
      }
    }
    let globalData = signature.signature + signature.trustedCommentData
    guard publicKey.isValidSignature(signature.globalSignature, for: globalData) else { return false }
    return true
  }
}

public struct Signature {
  public let untrustedComment: String
  public let signatureAlgorithm: SignatureAlgorithm
  public let keyID: Data
  public let signature: Data
  public let trustedCommentData: Data
  public let globalSignature: Data

  public var trustedComment: String? {
    return String(data: trustedCommentData, encoding: .utf8)
  }

  public init?<D>(text: D) where D : DataProtocol {
    let lines = text.split(separator: UInt8(ascii: "\n"), maxSplits: 4, omittingEmptySubsequences: false)
    guard lines.count == 4 || lines[4].isEmpty else { return nil }

    guard lines[0].starts(with: untrustedCommentHeader) else { return nil }
    guard let untrustedComment = String(data: Data(lines[0].suffix(from: untrustedCommentHeader.count as! D.Index)), encoding: .utf8) else { return nil }
    self.untrustedComment = untrustedComment

    guard let decLine2 = Data(base64Encoded: Data(lines[1]), options: []) else { return nil }
    guard decLine2.count == 74 else { return nil }
    guard let sigAlgo = SignatureAlgorithm(rawValue: decLine2.prefix(2)) else { return nil }
    self.signatureAlgorithm = sigAlgo
    self.keyID = decLine2[2..<10]
    self.signature = decLine2[10..<74]

    guard lines[2].starts(with: trustedCommentHeader) else { return nil }
    self.trustedCommentData = Data(lines[2]).suffix(from: trustedCommentHeader.count)

    guard let decLine4 = Data(base64Encoded: Data(lines[3]), options: []) else { return nil }
    guard decLine4.count == 64 else { return nil }
    self.globalSignature = decLine4
  }
}
