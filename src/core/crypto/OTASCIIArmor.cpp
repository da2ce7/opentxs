/************************************************************
 *
 *  OTASCIIArmor.cpp
 *
 */

/************************************************************
 -----BEGIN PGP SIGNED MESSAGE-----
 Hash: SHA1

 *                 OPEN TRANSACTIONS
 *
 *       Financial Cryptography and Digital Cash
 *       Library, Protocol, API, Server, CLI, GUI
 *
 *       -- Anonymous Numbered Accounts.
 *       -- Untraceable Digital Cash.
 *       -- Triple-Signed Receipts.
 *       -- Cheques, Vouchers, Transfers, Inboxes.
 *       -- Basket Currencies, Markets, Payment Plans.
 *       -- Signed, XML, Ricardian-style Contracts.
 *       -- Scripted smart contracts.
 *
 *  Copyright (C) 2010-2013 by "Fellow Traveler" (A pseudonym)
 *
 *  EMAIL:
 *  FellowTraveler@rayservers.net
 *
 *  BITCOIN:  1NtTPVVjDsUfDWybS4BwvHpG2pdS9RnYyQ
 *
 *  KEY FINGERPRINT (PGP Key in license file):
 *  9DD5 90EB 9292 4B48 0484  7910 0308 00ED F951 BB8E
 *
 *  OFFICIAL PROJECT WIKI(s):
 *  https://github.com/FellowTraveler/Moneychanger
 *  https://github.com/FellowTraveler/Open-Transactions/wiki
 *
 *  WEBSITE:
 *  http://www.OpenTransactions.org/
 *
 *  Components and licensing:
 *   -- Moneychanger..A Java client GUI.....LICENSE:.....GPLv3
 *   -- otlib.........A class library.......LICENSE:...LAGPLv3
 *   -- otapi.........A client API..........LICENSE:...LAGPLv3
 *   -- opentxs/ot....Command-line client...LICENSE:...LAGPLv3
 *   -- otserver......Server Application....LICENSE:....AGPLv3
 *  Github.com/FellowTraveler/Open-Transactions/wiki/Components
 *
 *  All of the above OT components were designed and written by
 *  Fellow Traveler, with the exception of Moneychanger, which
 *  was contracted out to Vicky C (bitcointrader4@gmail.com).
 *  The open-source community has since actively contributed.
 *
 *  -----------------------------------------------------
 *
 *   LICENSE:
 *   This program is free software: you can redistribute it
 *   and/or modify it under the terms of the GNU Affero
 *   General Public License as published by the Free Software
 *   Foundation, either version 3 of the License, or (at your
 *   option) any later version.
 *
 *   ADDITIONAL PERMISSION under the GNU Affero GPL version 3
 *   section 7: (This paragraph applies only to the LAGPLv3
 *   components listed above.) If you modify this Program, or
 *   any covered work, by linking or combining it with other
 *   code, such other code is not for that reason alone subject
 *   to any of the requirements of the GNU Affero GPL version 3.
 *   (==> This means if you are only using the OT API, then you
 *   don't have to open-source your code--only your changes to
 *   Open-Transactions itself must be open source. Similar to
 *   LGPLv3, except it applies to software-as-a-service, not
 *   just to distributing binaries.)
 *
 *   Extra WAIVER for OpenSSL, Lucre, and all other libraries
 *   used by Open Transactions: This program is released under
 *   the AGPL with the additional exemption that compiling,
 *   linking, and/or using OpenSSL is allowed. The same is true
 *   for any other open source libraries included in this
 *   project: complete waiver from the AGPL is hereby granted to
 *   compile, link, and/or use them with Open-Transactions,
 *   according to their own terms, as long as the rest of the
 *   Open-Transactions terms remain respected, with regard to
 *   the Open-Transactions code itself.
 *
 *   Lucre License:
 *   This code is also "dual-license", meaning that Ben Lau-
 *   rie's license must also be included and respected, since
 *   the code for Lucre is also included with Open Transactions.
 *   See Open-Transactions/src/otlib/lucre/LUCRE_LICENSE.txt
 *   The Laurie requirements are light, but if there is any
 *   problem with his license, simply remove the Lucre code.
 *   Although there are no other blind token algorithms in Open
 *   Transactions (yet. credlib is coming), the other functions
 *   will continue to operate.
 *   See Lucre on Github:  https://github.com/benlaurie/lucre
 *   -----------------------------------------------------
 *   You should have received a copy of the GNU Affero General
 *   Public License along with this program.  If not, see:
 *   http://www.gnu.org/licenses/
 *
 *   If you would like to use this software outside of the free
 *   software license, please contact FellowTraveler.
 *   (Unfortunately many will run anonymously and untraceably,
 *   so who could really stop them?)
 *
 *   DISCLAIMER:
 *   This program is distributed in the hope that it will be
 *   useful, but WITHOUT ANY WARRANTY; without even the implied
 *   warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 *   PURPOSE.  See the GNU Affero General Public License for
 *   more details.

 -----BEGIN PGP SIGNATURE-----
 Version: GnuPG v1.4.9 (Darwin)

 iQIcBAEBAgAGBQJRSsfJAAoJEAMIAO35UbuOQT8P/RJbka8etf7wbxdHQNAY+2cC
 vDf8J3X8VI+pwMqv6wgTVy17venMZJa4I4ikXD/MRyWV1XbTG0mBXk/7AZk7Rexk
 KTvL/U1kWiez6+8XXLye+k2JNM6v7eej8xMrqEcO0ZArh/DsLoIn1y8p8qjBI7+m
 aE7lhstDiD0z8mwRRLKFLN2IH5rAFaZZUvj5ERJaoYUKdn4c+RcQVei2YOl4T0FU
 LWND3YLoH8naqJXkaOKEN4UfJINCwxhe5Ke9wyfLWLUO7NamRkWD2T7CJ0xocnD1
 sjAzlVGNgaFDRflfIF4QhBx1Ddl6wwhJfw+d08bjqblSq8aXDkmFA7HeunSFKkdn
 oIEOEgyj+veuOMRJC5pnBJ9vV+7qRdDKQWaCKotynt4sWJDGQ9kWGWm74SsNaduN
 TPMyr9kNmGsfR69Q2Zq/FLcLX/j8ESxU+HYUB4vaARw2xEOu2xwDDv6jt0j3Vqsg
 x7rWv4S/Eh18FDNDkVRChiNoOIilLYLL6c38uMf1pnItBuxP3uhgY6COm59kVaRh
 nyGTYCDYD2TK+fI9o89F1297uDCwEJ62U0Q7iTDp5QuXCoxkPfv8/kX6lS6T3y9G
 M9mqIoLbIQ1EDntFv7/t6fUTS2+46uCrdZWbQ5RjYXdrzjij02nDmJAm2BngnZvd
 kamH0Y/n11lCvo1oQxM+
 =uSzz
 -----END PGP SIGNATURE-----
 **************************************************************/

#include "stdafx.hpp"

#include "crypto/OTASCIIArmor.hpp"
#include "crypto/OTCrypto.hpp"
#include "crypto/OTEnvelope.hpp"
#include "OTLog.hpp"
#include "OTStorage.hpp"

#include <fstream>
#include <memory>

#include <c5/zlib.h>
#include <c5/base64.h>

namespace opentxs
{

class OTASCIIArmor::OTASCIIArmorPrivdp
{
private:
    OTASCIIArmor* const backlink;

    typedef CryptoPP::BufferedTransformation::BlockingInputOnly
    errBlockingInputOnly;

public:
    explicit OTASCIIArmorPrivdp(OTASCIIArmor* const backlink)
        : backlink(backlink)
    {
    }

    void get_data(ot_data_t& out) const;
    void get_decoded_data(ot_data_t& out) const;
    void get_decompressed_data(ot_data_t& out,
                               const bool attempt = false) const;

    void compress_data(const ot_data_t& in, ot_data_t& out) const;
    void decompress_data(const ot_data_t& in, ot_data_t& out,
                         const bool attempt = false) const;

    void encode_data(const ot_data_t& in, ot_data_t& out) const;
    void decode_data(const ot_data_t& in, ot_data_t& out) const;
};

void OTASCIIArmor::OTASCIIArmorPrivdp::get_data(ot_data_t& out) const
{

    out.clear();

    const uint32_t len = backlink->GetLength();

    if (this->backlink->GetLength() < 1) return;

    out.assign(reinterpret_cast<const uint8_t*>(backlink->Get()),
               reinterpret_cast<const uint8_t*>(backlink->Get()) + len);

    if (out.empty()) {
        otErr << "String is empty" << __FUNCTION__ << "\n";
        return;
    }
}

void OTASCIIArmor::OTASCIIArmorPrivdp::get_decoded_data(ot_data_t& out) const
{

    out.clear();

    ot_data_t data;
    this->get_data(data);
    if (data.empty()) return;

    try
    {
        this->decode_data(data, data);
    }
    catch (const std::runtime_error&)
    {
        otErr << "Failed decode string in" << __FUNCTION__ << "\n";
        return;
    }

    if (data.empty()) {
        otErr << "Decoded string is empty" << __FUNCTION__ << "\n";
        return;
    }

    out = data;
}

void OTASCIIArmor::OTASCIIArmorPrivdp::get_decompressed_data(
    ot_data_t& out, const bool attempt) const
{

    out.clear();

    ot_data_t data, decompressed;
    this->get_decoded_data(data);
    if (data.empty()) return;

    try
    {
        this->decompress_data(data, decompressed, attempt);
        if (decompressed.empty()) {
            out = data;
            return;
        }
    }
    catch (const std::runtime_error&)
    {
        otErr << "Failed decompress string in" << __FUNCTION__ << "\n";
        return;
    }

    if (decompressed.empty()) {
        otErr << "Decompressed string is empty" << __FUNCTION__ << "\n";
        return;
    }

    out = decompressed;
}

void OTASCIIArmor::OTASCIIArmorPrivdp::compress_data(const ot_data_t& in,
                                                     ot_data_t& out) const
{

    const ot_data_t input = in;
    out.clear();
    if (input.empty()) return;

    CryptoPP::ZlibCompressor zibcompressor;

    try
    {
        zibcompressor.Initialize();
        zibcompressor.PutMessageEnd(&input.at(0), input.size());
        zibcompressor.Flush(1);
    }
    catch (errBlockingInputOnly e)
    {
        OT_FAIL_MSG("crypto++ failure \n");
        throw std::exception(e);
    }

    out.resize(static_cast<size_t>(zibcompressor.TotalBytesRetrievable()));
    out.resize(
        zibcompressor.Get(reinterpret_cast<uint8_t*>(&out.at(0)), out.size()));
}

void OTASCIIArmor::OTASCIIArmorPrivdp::decompress_data(const ot_data_t& in,
                                                       ot_data_t& out,
                                                       const bool attempt) const
{

    const ot_data_t input = in;
    out.clear();
    if (input.empty()) return;

    CryptoPP::ZlibDecompressor zlibdecompressor;

    try
    {
        zlibdecompressor.Initialize();
        zlibdecompressor.PutMessageEnd(&input.at(0), input.size());
        zlibdecompressor.Flush(1);
    }
    catch (errBlockingInputOnly e)
    {
        OT_FAIL_MSG("crypto++ failure \n");
        throw std::exception(e);
    }

    catch (CryptoPP::ZlibDecompressor::Err e)
    {

        if (attempt) {
            if (e.GetErrorType() ==
                CryptoPP::ZlibDecompressor::Err::INVALID_DATA_FORMAT) {
                return; // we are only trying.
            }
        }

        otErr << __FUNCTION__ << " Error: " << e.GetWhat() << "\n";

        std::string input_string(input.begin(), input.end());
        otErr << "Input: \n --- \n" << input_string << "\n --- \n";

        throw std::exception(e);
    }

    out.resize(static_cast<size_t>(zlibdecompressor.TotalBytesRetrievable()));
    out.resize(zlibdecompressor.Get(reinterpret_cast<uint8_t*>(&out.at(0)),
                                    out.size()));
}

void OTASCIIArmor::OTASCIIArmorPrivdp::encode_data(const ot_data_t& in,
                                                   ot_data_t& out) const
{

    const ot_data_t input = in;
    out.clear();
    if (input.empty()) return;

    CryptoPP::Base64Encoder base64Encoder;

    try
    {
        base64Encoder.PutMessageEnd(&input.at(0), input.size());
    }
    catch (errBlockingInputOnly e)
    {
        OT_FAIL_MSG("crypto++ failure \n");
        throw std::exception(e);
    }

    out.resize(static_cast<size_t>(base64Encoder.TotalBytesRetrievable()));
    out.resize(
        base64Encoder.Get(reinterpret_cast<uint8_t*>(&out.at(0)), out.size()));
}

void OTASCIIArmor::OTASCIIArmorPrivdp::decode_data(const ot_data_t& in,
                                                   ot_data_t& out) const
{

    const ot_data_t input = in;
    out.clear();
    if (input.empty()) return;

    CryptoPP::Base64Decoder base64Decoder;

    try
    {
        base64Decoder.PutMessageEnd(&input.at(0), input.size());
    }
    catch (errBlockingInputOnly e)
    {
        OT_FAIL_MSG("crypto++ failure \n");
        throw std::exception(e);
    }

    out.resize(static_cast<size_t>(base64Decoder.TotalBytesRetrievable()));
    out.resize(
        base64Decoder.Get(reinterpret_cast<uint8_t*>(&out.at(0)), out.size()));
}

const char* OT_BEGIN_ARMORED = "-----BEGIN OT ARMORED";
const char* OT_END_ARMORED = "-----END OT ARMORED";

const char* OT_BEGIN_ARMORED_escaped = "- -----BEGIN OT ARMORED";
const char* OT_END_ARMORED_escaped = "- -----END OT ARMORED";

const char* OT_BEGIN_SIGNED = "-----BEGIN SIGNED";
const char* OT_BEGIN_SIGNED_escaped = "- -----BEGIN SIGNED";

std::unique_ptr<OTDB::OTPacker> OTASCIIArmor::s_pPacker;

OTDB::OTPacker& OTASCIIArmor::GetPacker()
{
    if (nullptr ==
        s_pPacker) { // WARNING: Do not change OTDB_DEFAULT_PACKER below
                     // unless you also change SetAndPackData() since it
                     // ASSUMES this.
        s_pPacker.reset(OTDB::OTPacker::Create(
            OTDB_DEFAULT_PACKER)); // Protobuf is the only one that works on all
                                   // platforms right now.
        OT_ASSERT(nullptr != s_pPacker);
    }

    return *s_pPacker;
}

// Let's say you don't know if the input string is raw base64, or if it has
// bookends
// on it like -----BEGIN BLAH BLAH ...
// And if it DOES have Bookends, you don't know if they are escaped:  -
// -----BEGIN ...
// Let's say you just want an easy function that will figure that crap out, and
// load the
// contents up properly into an OTASCIIArmor object. (That's what this function
// will do.)
//
// str_bookend is a default.
// So you could make it more specific like, -----BEGIN ENCRYPTED KEY (or
// whatever.)
//
// static
bool OTASCIIArmor::LoadFromString(OTASCIIArmor& ascArmor,
                                  const OTString& strInput,
                                  std::string str_bookend)
{

    if (strInput.Contains(str_bookend)) // YES there are bookends around this.
    {
        const std::string str_escaped("- " + str_bookend);

        const bool bEscaped = strInput.Contains(str_escaped);

        OTString strLoadFrom(strInput);

        if (!ascArmor.LoadFromString(strLoadFrom, bEscaped)) // removes the
                                                             // bookends so we
                                                             // have JUST the
                                                             // coded part.
        {
            //          otErr << "%s: Failure loading string into OTASCIIArmor
            // object:\n\n%s\n\n",
            //                        __FUNCTION__, strInput.Get());
            return false;
        }
    }
    else
        ascArmor.Set(strInput.Get());

    return true;
}

// initializes blank.
OTASCIIArmor::OTASCIIArmor()
    : OTString()
{
}

// encodes
OTASCIIArmor::OTASCIIArmor(const OTString& strValue)
    : OTString(/*Don't pass here, since we're encoding.*/)
{
    SetString(strValue);
}

// encodes
OTASCIIArmor::OTASCIIArmor(const OTPayload& theValue)
    : OTString()
{
    SetData(theValue);
}

// encodes
OTASCIIArmor::OTASCIIArmor(const OTData& theValue)
    : OTString()
{
    SetData(theValue);
}

// Copies (already encoded)
OTASCIIArmor::OTASCIIArmor(const OTASCIIArmor& strValue)
    : OTString(dynamic_cast<const OTString&>(strValue))
    , dp(new OTASCIIArmorPrivdp(this))
{
}

// assumes envelope contains encrypted data;
// grabs that data in base64-form onto *this.
OTASCIIArmor::OTASCIIArmor(const OTEnvelope& theEnvelope)
    : OTString()
{
    theEnvelope.GetAsciiArmoredData(*this);
}

// copies (already encoded)
OTASCIIArmor::OTASCIIArmor(const char* szValue)
    : OTString(szValue)
{
}

// copies, assumes already encoded.
OTASCIIArmor& OTASCIIArmor::operator=(const char* szValue)
{
    Set(szValue);
    return *this;
}

// encodes
OTASCIIArmor& OTASCIIArmor::operator=(const OTString& strValue)
{
    if ((&strValue) != (&(dynamic_cast<const OTString&>(*this)))) {
        SetString(strValue);
    }
    return *this;
}

// encodes
OTASCIIArmor& OTASCIIArmor::operator=(const OTData& theValue)
{
    SetData(theValue);
    return *this;
}

// assumes is already encoded and just copies the encoded text
OTASCIIArmor& OTASCIIArmor::operator=(const OTASCIIArmor& strValue)
{
    if ((&strValue) != this) // prevent self-assignment
    {
        OTString::operator=(dynamic_cast<const OTString&>(strValue));
    }
    return *this;
}

/// if we pack, compress, encode on the way in, that means, therefore, we
/// need to decode, uncompress, then unpack on our way out. Right?
///
/// This function will base64-DECODE the string contents, then uncompress them
/// using
/// zlib, and then unpack the result using whatever is the default packer
/// (MsgPack, Protobuf, etc).
///
/// I originally added compression because message sizes were too big. Now I'm
/// adding packing,
/// to solve any issues of binary compatibility across various platforms.
//
bool OTASCIIArmor::GetAndUnpackString(
    OTString& strData, bool bLineBreaks) const // bLineBreaks=true
{
    strData.Release();
    if (GetLength() < 1) return true;

    ot_data_t packed_data;
    dp->get_decompressed_data(packed_data);

        std::string str_uncompressed = "";
        try {
            str_uncompressed = decompress_string(str_decoded);
        }
        catch (const std::runtime_error&) {
            otErr << "Failed decompressing string in "
                     "OTASCIIArmor::GetAndUnpackString.\n";
            return false;
        }

    // PUT THE PACKED BUFFER HERE, AND UNPACK INTO strData

    std::unique_ptr<OTDB::PackedBuffer> pBuffer(GetPacker().CreateBuffer());
    OT_ASSERT(nullptr != pBuffer);

    pBuffer->SetData(&packed_data.at(0), packed_data.size());

    std::unique_ptr<OTDB::OTDBString> pOTDBString(
        dynamic_cast<OTDB::OTDBString*>(
            OTDB::CreateObject(OTDB::STORED_OBJ_STRING)));
    OT_ASSERT(nullptr != pOTDBString);

    const bool bUnpacked = GetPacker().Unpack(*pBuffer, *pOTDBString);

    if (false == bUnpacked) {
        otErr << "Failed unpacking string in " << __FUNCTION__ << "\n";
        return false;
    }

    const std::vector<char> output(pOTDBString->m_string.begin(),
                                   pOTDBString->m_string.end());

    // This enforces the null termination. (using the 2nd parameter as
    // nEnforcedMaxLength)
    strData.Set(&output.at(0), output.size());

    return true;
}

// If adding packing STILL didn't make us binary compatible, then I need to try
// this next:
// Do the compression, THEN PACK...
// On the other way, UNPACK, THEN Uncompress.
//
// Right now I'm doing packing before compression, and unpacking after
// uncompression.
// Basically if that doesn't work (even though zlib appears to care about
// endian/platform)
// then switch the, (though that seems to make less logical sense to me.)
// Maybe have to pack before both? Seems crazy.

bool OTASCIIArmor::GetString(OTString& strData,
                             bool bLineBreaks) const // bLineBreaks=true
{
    return GetAndUnpackString(strData, bLineBreaks);
}

bool OTASCIIArmor::GetStringMap(std::map<std::string, std::string>& the_map,
                                bool bLineBreaks) const
{
    return GetAndUnpackStringMap(the_map, bLineBreaks);
}

bool OTASCIIArmor::GetAndUnpackStringMap(
    std::map<std::string, std::string>& the_map, bool bLineBreaks) const
{
    the_map.clear();
    if (GetLength() < 1) return true;

    ot_data_t packed_data;
    dp->get_decompressed_data(packed_data, true);
    OT_ASSERT(packed_data.empty());

    std::unique_ptr<OTDB::PackedBuffer> pBuffer(GetPacker().CreateBuffer());
    OT_ASSERT(nullptr != pBuffer);

    pBuffer->SetData(&packed_data.at(0), packed_data.size());

    std::unique_ptr<OTDB::StringMap> pStringMap(dynamic_cast<OTDB::StringMap*>(
        OTDB::CreateObject(OTDB::STORED_OBJ_STRING_MAP)));
    OT_ASSERT(nullptr != pStringMap);

    bool bUnpacked = GetPacker().Unpack(*pBuffer, *pStringMap);

    if (false == bUnpacked) {
        otErr << "Failed unpacking data in "
                 "OTASCIIArmor::GetAndUnpackStringMap.\n";
        return false;
    }

    the_map = pStringMap->the_map;
    return true;
}

bool OTASCIIArmor::SetStringMap(
    const std::map<std::string, std::string>& the_map, bool bLineBreaks)
{
    return SetAndPackStringMap(the_map, bLineBreaks);
}

bool OTASCIIArmor::SetAndPackStringMap(
    const std::map<std::string, std::string>& the_map, bool bLineBreaks)
{
    this->Release();
    if (the_map.size() < 1) return true;

    // Here I use the default storage context to create the object (the string
    // map.)
    // I also originally created OTASCIIArmor::GetPacker() using
    // OTDB_DEFAULT_PACKER,
    // so I know everything is compatible.
    //

    std::unique_ptr<OTDB::StringMap> pStringMap(dynamic_cast<OTDB::StringMap*>(
        OTDB::CreateObject(OTDB::STORED_OBJ_STRING_MAP)));
    OT_ASSERT(nullptr != pStringMap);

    pStringMap->the_map = the_map;

    // Now we PACK our data before compressing/encoding it.
    std::unique_ptr<OTDB::PackedBuffer> pBuffer(GetPacker().Pack(*pStringMap));

    if (nullptr == pBuffer) {
        otErr << "Failed packing data in" << __FUNCTION__ << "\n";
        return false;
    }

    ot_data_t packed_data(pBuffer->GetData(),
                          pBuffer->GetData() + pBuffer->GetSize());

    if (packed_data.empty()) {
        otErr << "Error while base64_encoding in " << __FUNCTION__ << "\n";
        return false;
    }

    ot_data_t encoded_data;

    this->dp->encode_data(packed_data, encoded_data);

    if (encoded_data.empty()) {
        otErr << "Error while base64_encoding in " << __FUNCTION__ << "\n";
        return false;
    }

    this->Set(reinterpret_cast<const char*>(&encoded_data.at(0)),
              encoded_data.size());

    return true;
}

// This function will base64 DECODE the string contents
// and return them as binary in theData
bool OTASCIIArmor::GetData(OTData& theData,
                           bool bLineBreaks) const // linebreaks=true
{
    return GetAndUnpackData(theData, bLineBreaks);
}

// This function will base64 DECODE the string contents
// and return them as binary in theData
//
bool OTASCIIArmor::GetAndUnpackData(OTData& theData,
                                    bool bLineBreaks) const // linebreaks=true
{
    theData.Release();
    if (GetLength() < 1) return true;

    ot_data_t packed_data;
    dp->get_decompressed_data(packed_data, true);
    OT_ASSERT(!packed_data.empty());

    std::unique_ptr<OTDB::PackedBuffer> pBuffer(GetPacker().CreateBuffer());
    OT_ASSERT(nullptr != pBuffer);

    pBuffer->SetData(&packed_data[0], packed_data.size());

    std::unique_ptr<OTDB::Blob> pBlob(
        dynamic_cast<OTDB::Blob*>(OTDB::CreateObject(OTDB::STORED_OBJ_BLOB)));
    OT_ASSERT(nullptr != pBlob);

    bool bUnpacked = GetPacker().Unpack(*pBuffer, *pBlob);

    if (false == bUnpacked) {
        otErr << "Failed unpacking data in " << __FUNCTION__ << "\n";
        return false;
    }

    theData.Assign(pBlob->m_memBuffer.data(),
                   static_cast<uint32_t>(pBlob->m_memBuffer.size()));

    return true;
}

// This function will base64 ENCODE theData,
// and then Set() that as the string contents.
bool OTASCIIArmor::SetData(const OTData& theData, bool bLineBreaks)
{
    return SetAndPackData(theData, bLineBreaks);
}

// This function will base64 ENCODE theData,
// and then Set() that as the string contents.
// Additionally it will pack and compress the data!
//
bool OTASCIIArmor::SetAndPackData(const OTData& theData, bool bLineBreaks)
{
    this->Release();
    if (theData.GetSize() < 1) return true;

    // Here I use the default storage context to create the object (the blob.)
    // I also originally created OTASCIIArmor::GetPacker() using
    // OTDB_DEFAULT_PACKER,
    // so I know everything is compatible.
    //
    std::unique_ptr<OTDB::Blob> pBlob(
        dynamic_cast<OTDB::Blob*>(OTDB::CreateObject(OTDB::STORED_OBJ_BLOB)));
    OT_ASSERT(nullptr != pBlob);

    pBlob->m_memBuffer.assign(
        static_cast<const uint8_t*>(theData.GetPointer()),
        static_cast<const uint8_t*>(theData.GetPointer()) + theData.GetSize());

    std::unique_ptr<OTDB::PackedBuffer> pBuffer(GetPacker().Pack(
        *pBlob)); // Now we PACK our data before compressing/encoding it.

    if (nullptr == pBuffer) {
        otErr << "Failed packing data in OTASCIIArmor::SetAndPackData. \n";
        return false;
    }

    const ot_data_t packed_data(pBuffer->GetData(),
                                pBuffer->GetData() + pBuffer->GetSize());
    ot_data_t encoded_data;

    this->dp->encode_data(packed_data, encoded_data);

    if (encoded_data.empty()) {
        otErr << "Error while base64_encoding in " << __FUNCTION__ << "\n";
        return false;
    }

    this->Set(reinterpret_cast<const char*>(&encoded_data.at(0)),
              encoded_data.size());

    return true;
}

/// This function first Packs the incoming string, using whatever is the default
/// packer. (MsgPack or Protobuf).
/// Then it Compresses the packed binary data using zlib. (ezcompress.)
/// Then it Base64-Encodes the compressed binary and sets it as a string on THIS
/// OBJECT.
///
/// I added these pieces 1-by-1 over time. At first the messages were too
/// int64_t, so I started compressing them.
/// Then they were not binary compatible across various platforms, so I added
/// the packing.
//
bool OTASCIIArmor::SetAndPackString(const OTString& strData,
                                    bool bLineBreaks) //=true
{
    this->Release();
    if (strData.GetLength() < 1) return true;

    // Here I use the default storage context to create the object (the blob.)
    // I also originally created OTASCIIArmor::GetPacker() using
    // OTDB_DEFAULT_PACKER,
    // so I know everything is compatible.
    //
    std::unique_ptr<OTDB::OTDBString> pOTDBString(
        dynamic_cast<OTDB::OTDBString*>(
            OTDB::CreateObject(OTDB::STORED_OBJ_STRING)));

    OT_ASSERT(nullptr != pOTDBString);

    pOTDBString->m_string.assign(strData.Get(),
                                 strData.Get() + strData.GetLength());

    std::unique_ptr<OTDB::PackedBuffer> pBuffer(GetPacker().Pack(*pOTDBString));
    // Now we PACK our string before compressing/encoding it.

    if (nullptr == pBuffer) {
        otErr << "Failed packing string in " << __FUNCTION__ << "\n";
        return false;
    }

    const ot_data_t packed_data(pBuffer->GetData(),
                                pBuffer->GetData() + pBuffer->GetSize());
    ot_data_t encoded_data;
    ot_data_t compressed_data;

    this->dp->compress_data(packed_data, compressed_data);
    if (compressed_data.empty()) {
        return false;
    }

    this->dp->encode_data(compressed_data, encoded_data);
    if (encoded_data.empty()) {
        return false;
    }

    this->Set(reinterpret_cast<const char*>(&encoded_data.at(0)),
              encoded_data.size());

    return true;
}

// This version is fully functional, and performs compression in addition to
// base64-encoding.
//
bool OTASCIIArmor::SetString(const OTString& strData, bool bLineBreaks) //=true
{
    return SetAndPackString(strData, bLineBreaks);
}

// This code reads up the file, discards the bookends, and saves only the
// gibberish itself.
bool OTASCIIArmor::LoadFromFile(const OTString& foldername,
                                const OTString& filename)
{
    OT_ASSERT(foldername.Exists());
    OT_ASSERT(filename.Exists());

    if (false == OTDB::Exists(foldername.Get(), filename.Get())) {
        otErr << "OTASCIIArmor::LoadFromFile: File does not exist: "
              << foldername << "" << OTLog::PathSeparator() << "" << filename
              << "\n";
        return false;
    }

    OTString strFileContents(OTDB::QueryPlainString(
        foldername.Get(), filename.Get())); // <=== LOADING FROM DATA STORE.

    if (strFileContents.GetLength() < 2) {
        otErr << "OTASCIIArmor::LoadFromFile: Error reading file: "
              << foldername << OTLog::PathSeparator() << filename << "\n";
        return false;
    }

    return LoadFromString(strFileContents);
}

bool OTASCIIArmor::LoadFromExactPath(const std::string& filename)
{
    std::ifstream fin(filename.c_str(), std::ios::binary);

    if (!fin.is_open()) {
        otWarn << "OTASCIIArmor::LoadFromExactPath: Failed opening file: "
               << filename << "\n";
        return false;
    }

    return LoadFrom_ifstream(fin);
}

// This code reads up the file, discards the bookends, and saves only the
// gibberish itself.
bool OTASCIIArmor::LoadFrom_ifstream(std::ifstream& fin)
{
    std::stringstream buffer;
    buffer << fin.rdbuf();

    std::string contents(buffer.str());

    OTString theString;
    theString.Set(contents.c_str());

    return LoadFromString(theString);
}

bool OTASCIIArmor::SaveToExactPath(const std::string& filename)
{
    std::ofstream fout(filename.c_str(), std::ios::out | std::ios::binary);

    if (!fout.is_open()) {
        otWarn << "OTASCIIArmor::SaveToExactPath: Failed opening file: "
               << filename << "\n";
        return false;
    }

    return SaveTo_ofstream(fout);
}

bool OTASCIIArmor::SaveTo_ofstream(std::ofstream& fout)
{
    OTString strOutput;
    std::string str_type("DATA"); // -----BEGIN OT ARMORED DATA-----

    if (WriteArmoredString(strOutput, str_type) && strOutput.Exists()) {
        // WRITE IT TO THE FILE
        //
        fout << strOutput;

        if (fout.fail()) {
            otErr << __FUNCTION__ << ": Failed saving to file.\n Contents:\n\n"
                  << strOutput << "\n\n";
            return false;
        }

        return true;
    }

    return false;
}

// const char * OT_BEGIN_ARMORED   = "-----BEGIN OT ARMORED";
// const char * OT_END_ARMORED     =   "-----END OT ARMORED";

bool OTASCIIArmor::WriteArmoredFile(
    const OTString& foldername, const OTString& filename,
    const // for "-----BEGIN OT LEDGER-----", str_type would contain "LEDGER"
    std::string str_type, // There's no default, to force you to enter the right
                          // string.
    bool bEscaped) const
{
    OT_ASSERT(foldername.Exists());
    OT_ASSERT(filename.Exists());

    OTString strOutput;

    if (WriteArmoredString(strOutput, str_type, bEscaped) &&
        strOutput.Exists()) {
        // WRITE IT TO THE FILE
        // StorePlainString will attempt to create all the folders leading up to
        // the path
        // for the output file.
        //
        bool bSaved = OTDB::StorePlainString(strOutput.Get(), foldername.Get(),
                                             filename.Get());

        if (!bSaved) {
            otErr << "OTASCIIArmor::WriteArmoredFile"
                  << ": Failed saving to file: %s%s%s\n\n Contents:\n\n"
                  << strOutput << "\n\n",
                foldername.Get(), OTLog::PathSeparator(), filename.Get();
            return false;
        }

        return true;
    }

    return false;
}

// const char * OT_BEGIN_ARMORED   = "-----BEGIN OT ARMORED";
// const char * OT_END_ARMORED     =   "-----END OT ARMORED";

bool OTASCIIArmor::WriteArmoredString(
    OTString& strOutput,
    const // for "-----BEGIN OT LEDGER-----", str_type would contain "LEDGER"
    std::string str_type, // There's no default, to force you to enter the right
                          // string.
    bool bEscaped) const
{
    const char* szEscape = "- ";

    OTString strTemp;
    strTemp.Format(
        "%s%s %s-----\n" // "%s-----BEGIN OT ARMORED %s-----\n"
        "Version: Open Transactions %s\n"
        "Comment: "
        "http://github.com/FellowTraveler/Open-Transactions/wiki\n\n" // todo
        // hardcoding.
        "%s"                // Should already have a newline at the bottom.
        "%s%s %s-----\n\n", // "%s-----END OT ARMORED %s-----\n"
        bEscaped ? szEscape : "",
        OT_BEGIN_ARMORED, str_type.c_str(), // "%s%s %s-----\n"
        OTLog::Version(),                   // "Version: Open Transactions %s\n"
        /* No variable */                   // "Comment:
        // http://github.com/FellowTraveler/Open-Transactions/wiki\n\n",
        Get(), //  "%s"     <==== CONTENTS OF THIS OBJECT BEING
               // WRITTEN...
        bEscaped ? szEscape : "", OT_END_ARMORED,
        str_type.c_str()); // "%s%s %s-----\n"

    strOutput.Concatenate("%s", strTemp.Get());

    return true;
}

// This code reads up the string, discards the bookends, and saves only the
// gibberish itself.
// the bEscaped option allows you to load a normal ASCII-Armored file if off,
// and allows
// you to load an escaped ASCII-armored file (such as inside the contracts when
// the public keys
// are escaped with a "- " before the rest of the ------- starts.)
//
bool OTASCIIArmor::LoadFromString(OTString& theStr, // input
                                  bool bEscaped,
                                  const // This szOverride sub-string determines
                                  // where the content starts, when loading.
                                  std::string str_override) // Default is
                                                            // "-----BEGIN"
{
    // Should never be 0 size, as default is "-----BEGIN"
    // But if you want to load a private key, try "-----BEGIN ENCRYPTED PRIVATE"
    // instead.
    // *smile*
    const std::string str_end_line =
        "-----END"; // Someday maybe allow parameterized option for this.

    const int32_t nBufSize = 2100;  // todo: hardcoding
    const int32_t nBufSize2 = 2048; // todo: hardcoding

    char buffer1[2100]; // todo: hardcoding

    std::fill(&buffer1[0], &buffer1[(nBufSize - 1)], 0); // Initializing to 0.

    bool bContentMode = false; // "Currently IN content mode."
    bool bHaveEnteredContentMode =
        false; // "Have NOT YET entered content mode."

    // Clear out whatever string might have been in there before.
    Release();

    // Load up the string from theStr,
    // (bookended by "-----BEGIN ... -----" and "END-----" messages)
    bool bIsEOF = false;
    theStr.reset(); // So we can call theStr.sgets(). Making sure position is at
                    // start of string.

    do {
        bIsEOF = !(theStr.sgets(buffer1, nBufSize2)); // 2048

        std::string line = buffer1;
        const char* pConstBuf = line.c_str();
        char* pBuf = (char*)pConstBuf;

        // It's not a blank line.
        if (line.length() < 2) {
            continue;
        }

        // if we're on a dashed line...
        else if (line.at(0) == '-' && line.at(2) == '-' && line.at(3) == '-' &&
                 (bEscaped ? (line.at(1) == ' ') : (line.at(1) == '-'))) {
            // If I just hit a dash, that means there are only two options:

            // a. I have not yet entered content mode, and potentially just now
            // entering it for the first time.
            if (!bHaveEnteredContentMode) {
                // str_override defaults to:  "-----BEGIN" (If you want to load
                // a private key instead,
                // Try passing "-----BEGIN ENCRYPTED PRIVATE" instead of going
                // with the default.)
                //
                if (line.find(str_override) != std::string::npos &&
                    line.at(0) == '-' && line.at(2) == '-' &&
                    line.at(3) == '-' &&
                    (bEscaped ? (line.at(1) == ' ') : (line.at(1) == '-'))) {
                    //                    otErr << "Reading ascii-armored
                    // contents...";
                    bHaveEnteredContentMode = true;
                    bContentMode = true;
                    continue;
                }
                else {
                    continue;
                }
            }

            // b. I am now LEAVING content mode!
            else if (bContentMode &&
                     // str_end_line is "-----END"
                     (line.find(str_end_line) != std::string::npos)) {
                //                otErr << "Finished reading ascii-armored
                // contents.\n";
                //                otErr << "Finished reading ascii-armored
                // contents:\n%s(END DATA)\n", Get());
                bContentMode = false;
                continue;
            }
        }

        // Else we're on a normal line, not a dashed line.
        else {
            if (bHaveEnteredContentMode && bContentMode) {
                if (line.compare(0, 8, "Version:") == 0) {
                    //                    otErr << "Skipping version line...\n";
                    continue;
                }
                if (line.compare(0, 8, "Comment:") == 0) {
                    //                    otErr << "Skipping comment line...\n";
                    continue;
                }
            }
        }

        // Here we save the line to member variables, if appropriate
        if (bContentMode) {
            Concatenate("%s\n", pBuf);
        }
    } while (!bIsEOF && (bContentMode || !bHaveEnteredContentMode));

    // reset the string position back to 0
    theStr.reset();

    if (!bHaveEnteredContentMode) {
        otErr << "Error in OTASCIIArmor::LoadFromString: EOF before "
                 "ascii-armored "
                 "content found, in:\n\n" << theStr << "\n\n";
        return false;
    }
    else if (bContentMode) {
        otErr
            << "Error in OTASCIIArmor::LoadFromString: EOF while still reading "
               "content, in:\n\n" << theStr << "\n\n";
        return false;
    }
    else
        return true;
}

OTASCIIArmor::~OTASCIIArmor()
{
    // ~OTString called automatically, which calls Release().
}

} // namespace opentxs
