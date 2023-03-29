// Copyright 2018 MPI-SWS and Valentin Wuestholz

// This file is part of Bran.
//
// Bran is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Bran is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with Bran.  If not, see <https://www.gnu.org/licenses/>.

package analysis

import (
	"encoding/hex"
	"strings"
	"testing"
	"fmt"

	"github.com/ethereum/go-ethereum/crypto"
)

var tests = []struct {
	name         string
	code         string
	prefix       []uint64
	canIgnore    bool
	failureCause string
}{
	{
		name:      "pass1.sol",
		code:      "606060405260043610603e5763ffffffff7c0100000000000000000000000000000000000000000000000000000000600035041663a5f3c23b81146043575b600080fd5b3415604d57600080fd5b6059600435602435606b565b60405190815260200160405180910390f35b01905600a165627a7a723058208bcdfc04a5b3a65c3e0eecccd1e5916770e5b0f029698391516775a7ce4924560029",
		prefix:    []uint64{0, 2, 4, 5, 7, 8, 9, 11, 12, 17, 47, 49, 50, 51, 52, 57, 58, 59, 61, 67, 68, 69, 70, 72, 77},
		canIgnore: true,
	},
	{
		name:      "pass2.sol",
		code:      "606060405260043610603f576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff168063a5f3c23b146044575b600080fd5b3415604e57600080fd5b606b60048080359060200190919080359060200190919050506081565b6040518082815260200191505060405180910390f35b6000600a9250600a91508183141515609d5760001515609c57fe5b5b929150505600a165627a7a72305820014abd0be74a47f5e80e7f899d1b26890df77747e81b1fc606a07af25bfeb94a00",
		prefix:    []uint64{0, 2, 4, 5, 7, 8, 9, 11, 12, 14, 15, 45, 46, 47, 52, 53, 54, 59, 60, 62, 68, 69, 70, 71, 73, 78},
		canIgnore: true,
	},
	{
		name:      "pass3.sol",
		code:      "606060405260043610603f576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff168063a5f3c23b146044575b600080fd5b3415604e57600080fd5b606b60048080359060200190919080359060200190919050506081565b6040518082815260200191505060405180910390f35b600081831315609257600a91506097565b601491505b5b818314151560aa576001830192506098565b600a8314151560b557fe5b929150505600a165627a7a72305820e80fc57294063e1bd531c2c37fc8d0d46c570ce12b174f710aae2a684b0dd5f200",
		prefix:    []uint64{0, 2, 4, 5, 7, 8, 9, 11, 12, 14, 15, 45, 46, 47, 52, 53, 54, 59, 60, 62, 68, 69, 70, 71, 73, 78, 79, 81, 83, 84, 85, 86, 87, 89, 90, 91, 92, 93, 94, 95, 96, 98, 99, 100, 101, 102, 103, 104, 106, 129, 130, 132, 133, 134, 135, 136, 138, 139, 141, 142, 143, 145},
		canIgnore: true,
	},
	{
		name:      "pass3-2",
		code:      "606060405260043610603f576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff168063a5f3c23b146044575b600080fd5b3415604e57600080fd5b606b60048080359060200190919080359060200190919050506081565b6040518082815260200191505060405180910390f35b600081831315609257600a91506097565b601491505b5b818314151560aa576001830192506098565b818314151560b457fe5b929150505600a165627a7a72305820c15169ccc5bf594d2a42e932740335ce3f0480741fee7256524b144ff186ca4000",
		prefix:    []uint64{0, 2, 4, 5, 7, 8, 9, 11, 12, 14, 15, 45, 46, 47, 52, 53, 54, 59, 60, 62, 68, 69, 70, 71, 73, 78, 79, 81, 83, 84, 85, 86, 87, 89, 90, 91, 92, 93, 94, 95, 96, 98, 99, 100, 101, 102, 103, 104, 106, 129, 130, 132, 133, 134, 135, 136, 138, 139},
		canIgnore: true,
	},
	{
		name:      "pass5",
		code:      "608060405260043610603f576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff16806387db03b7146044575b600080fd5b348015604f57600080fd5b50606c600480360381019080803590602001909291905050506082565b6040518082815260200191505060405180910390f35b600080600090506064831315609957602a9050609e565b602a90505b602a8114151560a957fe5b509190505600a165627a7a72305820c5f79a3baacae09e38a94d281480fa90b686ff88a1b59c4d72742617aff2ada200",
		prefix:    []uint64{0, 2, 4, 5, 7, 8, 9, 11, 12, 14, 15, 45, 46, 47, 52, 53, 54, 59, 60, 62, 68, 69, 70, 71, 72, 74, 79, 80, 81},
		canIgnore: true,
	},
	{
		name:      "pass6",
		code:      "608060405260043610610041576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff16806387db03b714610046575b600080fd5b34801561005257600080fd5b5061007160048036038101908080359060200190929190505050610087565b6040518082815260200191505060405180910390f35b6000806000905060008114156100b757601690506001810390506002810290506002818115156100b357fe5b0590505b6015811415156100c357fe5b60648114806100d25750601581145b156100de576002810290505b602a811415156100ea57fe5b602a811480156100fa5750601e81145b1561010f5760028181151561010b57fe5b0590505b602a8114151561011b57fe5b602a81141515610134576000151561012f57fe5b600a90505b600060028281151561014257fe5b07141561015157809050610160565b6000151561015b57fe5b600090505b602a8114151561016c57fe5b6000602a8218141515610184576000151561018357fe5b5b602a81141515610199576000151561019857fe5b5b602a811415156101ae57600015156101ad57fe5b5b6008801415156101c357600015156101c257fe5b5b60648114806101df5750602a811480156101de575060c88114155b5b15156101e757fe5b509190505600a165627a7a723058203a774b218a48a8acbc0103fb75dba4d8229c5cce648f9c5fb2b86f5fddcc09c000",
		prefix:    []uint64{0, 2, 4, 5, 7, 8, 9, 12, 13, 15, 16, 46, 47, 48, 53, 54, 55, 60, 61, 64, 70, 71, 72, 73, 74, 77, 82},
		canIgnore: true,
	},
	{
		name:      "pass7",
		code:      "608060405260043610603f576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff1680634f2be91f146044575b600080fd5b348015604f57600080fd5b506056606c565b6040518082815260200191505060405180910390f35b6000806000811560805760001515607f57fe5b5b811590508180608c5750805b1560bd5780801560995750805b1560af5780151581151514151560ab57fe5b60b9565b6000151560b857fe5b5b60c7565b6000151560c657fe5b5b5050905600a165627a7a7230582032d1cd4be812b0c0ebebf608b39d6f55f8bfcfff201ffbf9848e8d4d568ed9c200",
		prefix:    []uint64{0, 2, 4, 5, 7, 8, 9, 11, 12, 14, 15, 45, 46, 47, 52, 53, 54, 59, 60, 62, 68, 69, 70, 71, 72, 74, 79},
		canIgnore: true,
	},
	{
		name:      "pass8",
		code:      "608060405260043610603f576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff1680634f2be91f146044575b600080fd5b348015604f57600080fd5b506056606c565b6040518082815260200191505060405180910390f35b60008060008073ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff1614151560a757fe5b5050905600a165627a7a723058202beda531f149a609eb4db500f7f6c6fc587abc10bdcde3f4638c0d754a7428d000",
		prefix:    []uint64{0, 2, 4, 5, 7, 8, 9, 11, 12, 14, 15, 45, 46, 47, 52, 53, 54, 59, 60, 62, 68, 69, 70, 71, 72, 74, 79},
		canIgnore: true,
	},
	{
		name:      "pass9",
		code:      "608060405260043610610041576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff1680634f2be91f14610046575b600080fd5b34801561005257600080fd5b5061005b610071565b6040518082815260200191505060405180910390f35b6000807f48656c6c6f00000000000000000000000000000000000000000000000000000090507f48000000000000000000000000000000000000000000000000000000000000008160006005811015156100c757fe5b1a7f0100000000000000000000000000000000000000000000000000000000000000027effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff191614151561011557fe5b7f6f0000000000000000000000000000000000000000000000000000000000000081600460058110151561014557fe5b1a7f0100000000000000000000000000000000000000000000000000000000000000027effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff191614151561019357fe5b60058060ff161415156101a257fe5b50905600a165627a7a7230582041cbeb709bd33272fcddc00e7cfbaa849f0a9bf1b1364771fd3ab811281e617200",
		prefix:    []uint64{0, 2, 4, 5, 7, 8, 9, 12, 13, 15, 16, 46, 47, 48, 53, 54, 55, 60, 61, 64, 70, 71, 72, 73, 74, 77, 82},
		canIgnore: true,
	},
	{
		name:      "pass10",
		code:      "606060405260043610603f576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff168063a5f3c23b146044575b600080fd5b3415604e57600080fd5b606b60048080359060200190919080359060200190919050506081565b6040518082815260200191505060405180910390f35b600081831315609257600a91506097565b601491505b5b60038314151560ab576001830192506098565b60038314151560b657fe5b929150505600a165627a7a723058204bd03ac71c1cd336be2a519fbf4c975ed746313091e06485a11cdd0535271c6800",
		prefix:    []uint64{0, 2, 4, 5, 7, 8, 9, 11, 12, 14, 15, 45, 46, 47, 52, 53, 54, 59, 60, 62, 68, 69, 70, 71, 73, 78, 79, 81, 83, 84, 85, 86, 87, 89, 90, 91, 92, 93, 94, 95, 96, 98, 99, 100, 101, 102, 103, 104, 106, 129, 130, 132, 133, 134, 135, 136, 138, 139, 141, 142, 143, 145},
		canIgnore: true,
	},
	{
		name:      "pass11",
		code:      "606060405260043610603f576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff168063a5f3c23b146044575b600080fd5b3415604e57600080fd5b606b60048080359060200190919080359060200190919050506081565b6040518082815260200191505060405180910390f35b600081831315609257600a91506097565b601491505b5b82600414151560ab576001830192506098565b60048314151560b657fe5b929150505600a165627a7a72305820ff5678eb654ccf7de4afb4bb6b6ddd35a54801ba37d33ab5fd2b6ac8fd45db7a00",
		prefix:    []uint64{0, 2, 4, 5, 7, 8, 9, 11, 12, 14, 15, 45, 46, 47, 52, 53, 54, 59, 60, 62, 68, 69, 70, 71, 73, 78, 79, 81, 83, 84, 85, 86, 87, 89, 90, 91, 92, 93, 94, 95, 96, 98, 99, 100, 101, 102, 103, 104, 106, 129, 130, 132, 133, 134, 135, 136, 138, 139, 141, 142, 143, 145},
		canIgnore: true,
	},
	{
		name:      "pass12",
		code:      "606060405260043610603f576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff1680636f21b1f7146044575b600080fd5b3415604e57600080fd5b607a60048080351515906020019091908035151590602001909190803515159060200190919050506090565b6040518082815260200191505060405180910390f35b60008060009050841560a3576001810190505b831560af576001810190505b821560bb576001810190505b84801560c45750835b801560cc5750825b15151560d457fe5b5093925050505600a165627a7a723058200eb610dbc41b8ec8cb851db50c6407011ba1a11a57d963ab2da796db3a61279900",
		prefix:    []uint64{0, 2, 4, 5, 7, 8, 9, 11, 12, 14, 15, 45, 46, 47, 52, 53, 54, 59, 60, 62, 68, 69, 70, 71, 73, 78, 79, 81, 83, 84, 85, 86, 87, 88, 89, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 113, 114, 115, 116, 117, 118, 119, 121, 144, 145, 147, 148, 150, 151, 152, 153, 154, 156, 163},
		canIgnore: true,
	},
	{
		name:      "pass12-2",
		code:      "606060405260043610603f576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff1680636f21b1f7146044575b600080fd5b3415604e57600080fd5b607a60048080351515906020019091908035151590602001909190803515159060200190919050506090565b6040518082815260200191505060405180910390f35b60008060009050841560a3576001810190505b831560af576001810190505b821560bb576001810190505b84801560c45750835b801560cc5750825b15151560d457fe5b5093925050505600a165627a7a723058200eb610dbc41b8ec8cb851db50c6407011ba1a11a57d963ab2da796db3a61279900",
		prefix:    []uint64{0, 2, 4, 5, 7, 8, 9, 11, 12, 14, 15, 45, 46, 47, 52, 53, 54, 59, 60, 62, 68, 69, 70, 71, 73, 78, 79, 81, 83, 84, 85, 86, 87, 88, 89, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 113, 114, 115, 116, 117, 118, 119, 121, 144, 145, 147, 148, 150, 151, 152, 153, 154, 156, 157, 159, 160, 161, 162, 163, 164, 165, 166, 168, 175},
		canIgnore: true,
	},
	{
		name:      "pass13",
		code:      "606060405260043610603f576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff16806345557578146044575b600080fd5b3415604e57600080fd5b606460048080351515906020019091905050607a565b6040518082815260200191505060405180910390f35b600080600090508215608d576001810190505b82151515609657fe5b509190505600a165627a7a72305820252bac0afeed037de611846185c69d01ff7020e4ddf50633d2d84c942741509400",
		prefix:    []uint64{0, 2, 4, 5, 7, 8, 9, 11, 12, 14, 15, 45, 46, 47, 52, 53, 54, 59, 60, 62, 68, 69, 70, 71, 73, 78, 79, 81, 83, 84, 85, 86, 87, 88, 89, 91, 92, 93, 94, 95, 96, 97, 99, 122, 123, 125, 126, 128, 129, 130, 131, 132, 134, 141},
		canIgnore: true,
	},
	{
		name:      "pass14",
		code:      "606060405260043610603f576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff1680634f2be91f146044575b600080fd5b3415604e57600080fd5b6054606a565b6040518082815260200191505060405180910390f35b6000602a9050905600a165627a7a723058205a69a5ac4878874f6b5d174117fcfd83b766ec2ff68aa689e605bb9db80baffa00",
		prefix:    []uint64{},
		canIgnore: true,
	},
	{
		name:         "fail1",
		code:         "606060405260043610603f576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff168063a5f3c23b146044575b600080fd5b3415604e57600080fd5b606b60048080359060200190919080359060200190919050506081565b6040518082815260200191505060405180910390f35b6000600a9250601491508183141515609d5760001515609c57fe5b5b929150505600a165627a7a7230582099f5abb3690f266c48f2523a5165b9fcb7aa53d4ead1f42f69c0641376a4f7b60029",
		prefix:       []uint64{0, 2, 4, 5, 7, 8, 9, 11, 12, 14, 15, 45, 46, 47, 52, 53, 54, 59, 60, 62, 68, 69, 70, 71, 73, 78},
		canIgnore:    false,
		failureCause: "invalid-opcode",
	},
	{
		name:         "fail2",
		code:         "606060405260043610603f576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff168063a5f3c23b146044575b600080fd5b3415604e57600080fd5b606b60048080359060200190919080359060200190919050506081565b6040518082815260200191505060405180910390f35b6000818314151560955760001515609457fe5b5b929150505600a165627a7a723058202842962e9f90c37963cc2189b6515e25e6536b57b6cbbe06f0f530424688273c00",
		prefix:       []uint64{0, 2, 4, 5, 7, 8, 9, 11, 12, 14, 15, 45, 46, 47, 52, 53, 54, 59, 60, 62, 68, 69, 70, 71, 73, 78},
		canIgnore:    false,
		failureCause: "invalid-opcode",
	},
	{
		name:         "pass3-shorter-prefix",
		code:         "606060405260043610603f576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff168063a5f3c23b146044575b600080fd5b3415604e57600080fd5b606b60048080359060200190919080359060200190919050506081565b6040518082815260200191505060405180910390f35b600081831315609257600a91506097565b601491505b5b818314151560aa576001830192506098565b600a8314151560b557fe5b929150505600a165627a7a72305820e80fc57294063e1bd531c2c37fc8d0d46c570ce12b174f710aae2a684b0dd5f200",
		prefix:       []uint64{0, 2, 4, 5, 7, 8, 9, 11, 12, 14, 15, 45, 46, 47, 52, 53, 54, 59, 60, 62, 68, 69, 70, 71, 73, 78, 79, 81, 83, 84, 85, 86, 87, 89, 90, 91, 92, 93, 94, 95, 96, 98, 99, 100, 101, 102, 103, 104, 106, 129},
		canIgnore:    false,
		failureCause: "invalid-opcode",
	},
	{
		name:         "pass3-fail2",
		code:         "606060405260043610603f576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff168063a5f3c23b146044575b600080fd5b3415604e57600080fd5b606b60048080359060200190919080359060200190919050506081565b6040518082815260200191505060405180910390f35b600081831315609257600a91506097565b601491505b5b818314151560aa576001830192506098565b818314151560b457fe5b929150505600a165627a7a72305820c15169ccc5bf594d2a42e932740335ce3f0480741fee7256524b144ff186ca4000",
		prefix:       []uint64{0, 2, 4, 5, 7, 8, 9, 11, 12, 14, 15, 45, 46, 47, 52, 53, 54, 59, 60, 62, 68, 69, 70, 71, 73, 78, 79, 81, 83, 84, 85, 86, 87, 89, 90, 91, 92, 93, 94, 95, 96, 98, 99, 100, 101, 102, 103, 104, 106, 129, 130, 132, 133, 134, 135, 136, 138},
		canIgnore:    false,
		failureCause: "invalid-opcode",
	},
	{
		name:         "fail5",
		code:         "608060405260043610603f576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff16806387db03b7146044575b600080fd5b348015604f57600080fd5b50606c600480360381019080803590602001909291905050506082565b6040518082815260200191505060405180910390f35b600080600090506064831315609957602a9050609e565b602b90505b602a8114151560a957fe5b509190505600a165627a7a723058206337e204e54c69d94045e79306d207e44647fd3aa42afc237914692ac49dd88b00",
		prefix:       []uint64{0, 2, 4, 5, 7, 8, 9, 11, 12, 14, 15, 45, 46, 47, 52, 53, 54, 59, 60, 62, 68, 69, 70, 71, 72, 74, 79, 80, 81},
		canIgnore:    false,
		failureCause: "invalid-opcode",
	},
	{
		name:         "fail6",
		code:         "606060405260043610603f576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff16806345557578146044575b600080fd5b3415604e57600080fd5b606460048080351515906020019091905050607a565b6040518082815260200191505060405180910390f35b600080600090508215608d576001810190505b821515609557fe5b509190505600a165627a7a723058209f2f9f23a227d517776de1e8c286e5e6f06e2e42da2d223de7602810d0f1b32b00",
		prefix:       []uint64{0, 2, 4, 5, 7, 8, 9, 11, 12, 14, 15, 45, 46, 47, 52, 53, 54, 59, 60, 62, 68, 69, 70, 71, 73, 78, 79, 81, 83, 84, 85, 86, 87, 88, 89, 91, 92, 93, 94, 95, 96, 97, 99, 122, 123, 125, 126, 128, 129, 130, 131, 132, 134, 135},
		canIgnore:    false,
		failureCause: "invalid-opcode",
	},
	{
		name:         "pass12-fail",
		code:         "606060405260043610603f576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff1680636f21b1f7146044575b600080fd5b3415604e57600080fd5b607a60048080351515906020019091908035151590602001909190803515159060200190919050506090565b6040518082815260200191505060405180910390f35b60008060009050841560a3576001810190505b831560af576001810190505b821560bb576001810190505b84801560c45750835b801560cc5750825b15151560d457fe5b5093925050505600a165627a7a723058200eb610dbc41b8ec8cb851db50c6407011ba1a11a57d963ab2da796db3a61279900",
		prefix:       []uint64{0, 2, 4, 5, 7, 8, 9, 11, 12, 14, 15, 45, 46, 47, 52, 53, 54, 59, 60, 62, 68, 69, 70, 71, 73, 78, 79, 81, 83, 84, 85, 86, 87, 88, 89, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 113, 114, 115, 116, 117, 118, 119, 121, 144, 145, 147, 148, 150, 151, 152, 153, 154, 156, 157},
		canIgnore:    false,
		failureCause: "invalid-opcode",
	},
}

func TestConstantPropagation(t *testing.T) {
	for _, tc := range tests {
		code, err := hex.DecodeString(tc.code)
		if err != nil {
			t.Errorf("[%v] error decoding contract code: %v", tc.name, tc.code)
			continue
		}
		fmt.Println(tc.name, " prefix length: ", len(tc.prefix))
		a := NewLookaheadAnalyzer()
		a.Start(1, code, crypto.Keccak256Hash(code).Bytes())
		for _, pc := range tc.prefix {
			a.AppendPrefixInstruction(1, pc)
		}
																					// can set target location here 
																					// AddTargetInstruction(codeHash []byte, pc uint64)
		canIgnore, _, cause, _, err := a.CanIgnoreSuffix(1)							// core
		if err != nil {
			t.Errorf("[%v] analysis ended with an error: %v", tc.name, err)
			continue
		}
		if tc.canIgnore {
			if !canIgnore {
				t.Errorf("[%v] expected analysis to succeed, but it failed with failure cause '%v'", tc.name, cause)
				continue
			}
		} else {
			if canIgnore {
				t.Errorf("[%v] expected analysis to report failure, but it didn't", tc.name)
				continue
			}
			if len(tc.failureCause) > 0 && !strings.Contains(cause, tc.failureCause) {
				t.Errorf("[%v] expected failure cause to contain '%v', but got '%v'", tc.name, tc.failureCause, cause)
				continue
			}
		}													// no error :
															//           tc: true, result: true
															//			 tc: false, result: false, cause in tc.failureCause
	}
}
