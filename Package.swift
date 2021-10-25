// swift-tools-version:5.3
// SPDX-License-Identifier: MIT
// Copyright 2021 Stephen Larew

import PackageDescription

let package = Package(
  name: "swift-minisign",
  platforms: [.macOS(.v10_15)],
  products: [
    .library(
      name: "Minisign",
      targets: ["Minisign"]),
  ],
  dependencies: [
    .package(url: "https://github.com/apple/swift-crypto", from: "2.0.0"),
    .package(url: "https://github.com/slarew/swift-crypto-blake2", from: "2.0.0")
  ],
  targets: [
    .target(
      name: "Minisign",
      dependencies: [
        .product(name: "Crypto", package: "swift-crypto"),
        .product(name: "BLAKE2", package: "swift-crypto-blake2")
      ]),
    .testTarget(
      name: "MinisignTests",
      dependencies: ["Minisign"]),
  ]
)
