#!/usr/bin/env python3
"""Decode and display JWT claims locally for comparison with ESP32"""

import base64
import json
import sys
from datetime import datetime


def base64url_decode(data):
    """Decode base64url (URL-safe base64 without padding)"""
    # Add padding if needed
    missing_padding = len(data) % 4
    if missing_padding:
        data += '=' * (4 - missing_padding)
    # Replace URL-safe characters
    data = data.replace('-', '+').replace('_', '/')
    return base64.b64decode(data)


def decode_jwt(token):
    """Decode and display JWT parts"""
    try:
        parts = token.split('.')
        if len(parts) != 3:
            print("❌ Invalid JWT format (expected 3 parts separated by dots)")
            return False
        
        header_b64, payload_b64, signature_b64 = parts
        
        # Decode header
        header_json = base64url_decode(header_b64)
        header = json.loads(header_json)
        
        # Decode payload
        payload_json = base64url_decode(payload_b64)
        payload = json.loads(payload_json)
        
        print("=" * 80)
        print("JWT HEADER:")
        print(json.dumps(header, indent=2))
        print("\n" + "=" * 80)
        print("JWT PAYLOAD (CLAIMS):")
        print(json.dumps(payload, indent=2))
        
        print("\n" + "=" * 80)
        print("KEY CLAIMS:")
        
        if 'exp' in payload:
            exp_ts = payload['exp']
            exp_dt = datetime.fromtimestamp(exp_ts)
            now = datetime.now()
            diff = exp_ts - int(now.timestamp())
            print(f"  exp: {exp_ts} ({exp_dt})")
            print(f"       Expires in: {diff} seconds")
            if diff < 0:
                print("       ⚠️  TOKEN IS EXPIRED!")
        
        if 'iat' in payload:
            iat_ts = payload['iat']
            iat_dt = datetime.fromtimestamp(iat_ts)
            print(f"  iat: {iat_ts} ({iat_dt})")
        
        if 'iss' in payload:
            print(f"  iss: {payload['iss']}")
        
        if 'aud' in payload:
            print(f"  aud: {payload['aud']}")
        
        if 'sub' in payload:
            print(f"  sub: {payload['sub']}")
        
        if 'azp' in payload:
            print(f"  azp: {payload['azp']}")
        
        if 'preferred_username' in payload:
            print(f"  username: {payload['preferred_username']}")
        
        print("\n" + "=" * 80)
        print("BASE64 LENGTHS:")
        print(f"  Header:    {len(header_b64)} chars")
        print(f"  Payload:   {len(payload_b64)} chars")
        print(f"  Signature: {len(signature_b64)} chars")
        
        print("\n" + "=" * 80)
        print("DECODED LENGTHS:")
        print(f"  Header JSON:  {len(header_json)} bytes")
        print(f"  Payload JSON: {len(payload_json)} bytes")
        
        print("\n" + "=" * 80)
        print("PAYLOAD JSON PREVIEW (first 150 chars):")
        print(payload_json[:150])
        
        return True
        
    except Exception as e:
        print(f"❌ Error decoding JWT: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    if len(sys.argv) < 2:
        print("Usage: decode_jwt.py <JWT_TOKEN>")
        print("\nExample:")
        print("  ./scripts/decode_jwt.py eyJhbGc...")
        return 1
    
    token = sys.argv[1].strip()
    
    if decode_jwt(token):
        return 0
    else:
        return 1


if __name__ == "__main__":
    sys.exit(main())
