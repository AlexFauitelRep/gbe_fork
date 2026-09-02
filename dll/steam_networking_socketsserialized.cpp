/* Copyright (C) 2019 Mr Goldberg
   This file is part of the Goldberg Emulator

   The Goldberg Emulator is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   The Goldberg Emulator is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the Goldberg Emulator; if not, see
   <http://www.gnu.org/licenses/>.  */

#include "dll/steam_networking_socketsserialized.h"
#include "dll/gbe_sdr_cert_data.h"
#include "dll/local_storage.h"


void Steam_Networking_Sockets_Serialized::steam_callback(void *object, Common_Message *msg)
{
    // PRINT_DEBUG_ENTRY();

    Steam_Networking_Sockets_Serialized *steam_networkingsockets = (Steam_Networking_Sockets_Serialized *)object;
    steam_networkingsockets->Callback(msg);
}

void Steam_Networking_Sockets_Serialized::steam_run_every_runcb(void *object)
{
    // PRINT_DEBUG_ENTRY();

    Steam_Networking_Sockets_Serialized *steam_networkingsockets = (Steam_Networking_Sockets_Serialized *)object;
    steam_networkingsockets->RunCallbacks();
}

Steam_Networking_Sockets_Serialized::Steam_Networking_Sockets_Serialized(class Settings *settings, class Networking *network, class SteamCallResults *callback_results, class SteamCallBacks *callbacks, class RunEveryRunCB *run_every_runcb)
{
    this->settings = settings;
    this->network = network;
    this->callback_results = callback_results;
    this->callbacks = callbacks;
    this->run_every_runcb = run_every_runcb;

    this->network->setCallback(CALLBACK_ID_USER_STATUS, settings->get_local_steam_id(), &Steam_Networking_Sockets_Serialized::steam_callback, this);
    this->run_every_runcb->add(&Steam_Networking_Sockets_Serialized::steam_run_every_runcb, this);

}

Steam_Networking_Sockets_Serialized::~Steam_Networking_Sockets_Serialized()
{
    this->network->rmCallback(CALLBACK_ID_USER_STATUS, settings->get_local_steam_id(), &Steam_Networking_Sockets_Serialized::steam_callback, this);
    this->run_every_runcb->remove(&Steam_Networking_Sockets_Serialized::steam_run_every_runcb, this);
}

void Steam_Networking_Sockets_Serialized::SendP2PRendezvous( CSteamID steamIDRemote, uint32 unConnectionIDSrc, const void *pMsgRendezvous, uint32 cbRendezvous )
{
    PRINT_DEBUG_TODO();
    std::lock_guard<std::recursive_mutex> lock(global_mutex);
}

void Steam_Networking_Sockets_Serialized::SendP2PConnectionFailure( CSteamID steamIDRemote, uint32 unConnectionIDDest, uint32 nReason, const char *pszReason )
{
    PRINT_DEBUG_TODO();
    std::lock_guard<std::recursive_mutex> lock(global_mutex);
}

SteamAPICall_t Steam_Networking_Sockets_Serialized::GetCertAsync()
{
    PRINT_DEBUG_ENTRY();
    std::lock_guard<std::recursive_mutex> lock(global_mutex);
    // Precomputed self-issued SDR certificate. The leaf cert is signed by our own
    // fixed Ed25519 CA; the CA public key is patched into steamnetworkingsockets.dll
    // (replacing Valve's hardcoded root) so the client's CertStore accepts it and
    // AuthStatus becomes OK. Without this the client reports "Cert request returned
    // invalid cert" and gates the inventory/econ UI behind "Steam connection error".
    struct SteamNetworkingSocketsCert_t data = {};
    data.m_eResult = k_EResultOK;
    data.m_caKeyID = GBE_SDR_CA_KEY_ID;   // single CA for the whole cert pool

    // Per-machine SDR cert (Route 2): prefer cert/sig/privkey from
    // <game>\steam_settings\sdr_cert\ so each machine presents a certificate whose
    // identity == its OWN SteamID. Required for LAN: if two machines share the same
    // cert identity, the client's GameNetworkingSockets treats the remote peer as
    // "self" and the connect stalls in "finding route" until timeout. Falls back to
    // the baked (76561199172302864) cert when the folder/files are absent or malformed
    // (dev / single-PC use). The CA key id is always the baked one (one CA per pool).
    {
        const std::string dir = Local_Storage::get_game_settings_path() + "sdr_cert" + PATH_SEPARATOR;
        char certBuf[sizeof(data.m_certOrMsg)];
        char sigBuf[sizeof(data.m_signature)];
        char privBuf[sizeof(data.m_privKey)];
        int nCert = Local_Storage::get_file_data(dir + "cert.bin",    certBuf, (unsigned int)sizeof(certBuf));
        int nSig  = Local_Storage::get_file_data(dir + "sig.bin",     sigBuf,  (unsigned int)sizeof(sigBuf));
        int nPriv = Local_Storage::get_file_data(dir + "id_priv.bin", privBuf, (unsigned int)sizeof(privBuf));

        if (nCert > 0 && nCert <= (int)sizeof(data.m_certOrMsg) && nSig == 64 && nPriv == 64) {
            data.m_cbCert      = (uint32)nCert;  memcpy(data.m_certOrMsg, certBuf, (size_t)nCert);
            data.m_cbSignature = (uint32)nSig;   memcpy(data.m_signature, sigBuf,  (size_t)nSig);
            data.m_cbPrivKey   = (uint32)nPriv;  memcpy(data.m_privKey,   privBuf, (size_t)nPriv);
            PRINT_DEBUG("GetCertAsync: per-machine SDR cert loaded from steam_settings/sdr_cert (cert=%d)", nCert);
        } else {
            data.m_cbCert      = GBE_SDR_CERT_LEN;           memcpy(data.m_certOrMsg, GBE_SDR_CERT, GBE_SDR_CERT_LEN);
            data.m_cbSignature = GBE_SDR_SIG_LEN;            memcpy(data.m_signature, GBE_SDR_SIG, GBE_SDR_SIG_LEN);
            data.m_cbPrivKey   = sizeof(GBE_SDR_ID_PRIV);    memcpy(data.m_privKey,   GBE_SDR_ID_PRIV, sizeof(GBE_SDR_ID_PRIV));
            PRINT_DEBUG("GetCertAsync: baked static SDR cert (76561199172302864 fallback)");
        }
    }

    auto ret = callback_results->addCallResult(data.k_iCallback, &data, sizeof(data));
    callbacks->addCBResult(data.k_iCallback, &data, sizeof(data));
    return ret;
}

int Steam_Networking_Sockets_Serialized::GetNetworkConfigJSON( void *buf, uint32 cbBuf, const char *pszLauncherPartner )
{
    PRINT_DEBUG_TODO();
    std::lock_guard<std::recursive_mutex> lock(global_mutex);
    return 0;
}

int Steam_Networking_Sockets_Serialized::GetNetworkConfigJSON( void *buf, uint32 cbBuf )
{
    PRINT_DEBUG_TODO();
    std::lock_guard<std::recursive_mutex> lock(global_mutex);
    return GetNetworkConfigJSON(buf, cbBuf, "");
}

void Steam_Networking_Sockets_Serialized::CacheRelayTicket( const void *pTicket, uint32 cbTicket )
{
    PRINT_DEBUG_TODO();
    std::lock_guard<std::recursive_mutex> lock(global_mutex);
}

uint32 Steam_Networking_Sockets_Serialized::GetCachedRelayTicketCount()
{
    PRINT_DEBUG_TODO();
    std::lock_guard<std::recursive_mutex> lock(global_mutex);
    return 0;
}

int Steam_Networking_Sockets_Serialized::GetCachedRelayTicket( uint32 idxTicket, void *buf, uint32 cbBuf )
{
    PRINT_DEBUG_TODO();
    std::lock_guard<std::recursive_mutex> lock(global_mutex);
    return 0;
}

void Steam_Networking_Sockets_Serialized::PostConnectionStateMsg( const void *pMsg, uint32 cbMsg )
{
    PRINT_DEBUG_TODO();
    std::lock_guard<std::recursive_mutex> lock(global_mutex);
}

bool Steam_Networking_Sockets_Serialized::GetSTUNServer(int dont_know, char *buf, unsigned int len)
{
    PRINT_DEBUG_TODO();
    std::lock_guard<std::recursive_mutex> lock(global_mutex);
    return false;
}

bool Steam_Networking_Sockets_Serialized::BAllowDirectConnectToPeer(SteamNetworkingIdentity const &identity)
{
    PRINT_DEBUG_TODO();
    std::lock_guard<std::recursive_mutex> lock(global_mutex);
    return true;
}

int Steam_Networking_Sockets_Serialized::BeginAsyncRequestFakeIP(int a)
{
    PRINT_DEBUG_TODO();
    std::lock_guard<std::recursive_mutex> lock(global_mutex);
    return true;
}

void Steam_Networking_Sockets_Serialized::RunCallbacks()
{
    
}

void Steam_Networking_Sockets_Serialized::Callback(Common_Message *msg)
{
    if (msg->has_low_level()) {
        if (msg->low_level().type() == Low_Level::CONNECT) {
            
        }

        if (msg->low_level().type() == Low_Level::DISCONNECT) {

        }
    }
}
