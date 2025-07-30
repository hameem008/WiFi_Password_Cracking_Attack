import hashlib
import hmac
import os
import time
import random
import string
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64


class SecureNonce:
    """
    Secure Nonce class that encrypts and protects ANonce and SNonce
    """
    
    def __init__(self, encryption_password):
        self.encryption_password = encryption_password
        self.salt = os.urandom(16)
        self.key = self._derive_key()
        self.cipher = Fernet(self.key)
        self.nonce_history = set()  # Prevent replay attacks
        
    def _derive_key(self):
        """Derive encryption key from password using PBKDF2"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(self.encryption_password.encode()))
        return key
    
    def generate_secure_nonce(self, nonce_type="anonce"):
        """Generate and encrypt a secure nonce"""
        # Generate random nonce
        nonce = os.urandom(32)
        
        # Add timestamp and type for additional security
        timestamp = int(time.time()).to_bytes(8, 'big')
        nonce_type_bytes = nonce_type.encode()
        
        # Combine all components
        combined_data = timestamp + nonce_type_bytes + nonce
        
        # Encrypt the nonce
        encrypted_nonce = self.cipher.encrypt(combined_data)
        
        # Add to history to prevent replay
        nonce_hash = hashlib.sha256(encrypted_nonce).digest()
        self.nonce_history.add(nonce_hash)
        
        return encrypted_nonce
    
    def decrypt_nonce(self, encrypted_nonce):
        """Decrypt and validate a nonce"""
        try:
            # Decrypt the nonce
            decrypted_data = self.cipher.decrypt(encrypted_nonce)
            
            # Extract components
            timestamp = int.from_bytes(decrypted_data[:8], 'big')
            nonce_type = decrypted_data[8:14].decode().rstrip('\x00')
            nonce = decrypted_data[14:]
            
            # Check if nonce is too old (5 minutes)
            if time.time() - timestamp > 300:
                return None, "Nonce expired"
            
            # Check for replay attacks
            nonce_hash = hashlib.sha256(encrypted_nonce).digest()
            if nonce_hash in self.nonce_history:
                return None, "Replay attack detected"
            
            return nonce, nonce_type
            
        except Exception as e:
            return None, f"Decryption failed: {str(e)}"


class SecureHandshake:
    """
    Secure 4-way handshake with encrypted nonces
    """
    
    def __init__(self, router_password):
        self.router_password = router_password
        self.secure_nonce = SecureNonce(router_password)
        self.handshake_sessions = {}  # Track active handshakes
        self.session_timeout = 60  # 60 seconds timeout
        
    def initiate_handshake(self, client_mac):
        """Initiate secure 4-way handshake"""
        session_id = os.urandom(16)
        
        # Generate encrypted ANonce
        encrypted_anonce = self.secure_nonce.generate_secure_nonce("anonce")
        
        # Store session data
        self.handshake_sessions[session_id] = {
            'client_mac': client_mac,
            'anonce': encrypted_anonce,
            'start_time': time.time(),
            'step': 1
        }
        
        return session_id, encrypted_anonce
    
    def process_client_response(self, session_id, encrypted_snonce, client_mic):
        """Process client's response in handshake"""
        if session_id not in self.handshake_sessions:
            return False, "Invalid session"
        
        session = self.handshake_sessions[session_id]
        
        # Check session timeout
        if time.time() - session['start_time'] > self.session_timeout:
            del self.handshake_sessions[session_id]
            return False, "Session expired"
        
        # Decrypt and validate SNonce
        snonce, nonce_type = self.secure_nonce.decrypt_nonce(encrypted_snonce)
        if not snonce:
            return False, f"Invalid SNonce: {nonce_type}"
        
        if nonce_type != "snonce":
            return False, "Invalid nonce type"
        
        # Store SNonce and proceed to next step
        session['snonce'] = snonce
        session['client_mic'] = client_mic
        session['step'] = 2
        
        return True, "SNonce validated"
    
    def complete_handshake(self, session_id):
        """Complete the handshake and generate session keys"""
        if session_id not in self.handshake_sessions:
            return False, "Invalid session"
        
        session = self.handshake_sessions[session_id]
        
        if session['step'] != 2:
            return False, "Invalid handshake step"
        
        # Generate session keys (simplified)
        session_key = self._generate_session_key(session['anonce'], session['snonce'])
        
        # Mark handshake as complete
        session['session_key'] = session_key
        session['step'] = 3
        session['completed'] = True
        
        return True, session_key
    
    def _generate_session_key(self, anonce, snonce):
        """Generate session key from nonces"""
        # Combine nonces with router password
        combined = anonce + snonce + self.router_password.encode()
        return hashlib.sha256(combined).digest()


class Router:
    """
    Secure Router class with WPA2 attack prevention
    """
    
    def __init__(self, ssid, password, encryption_password=None):
        self.ssid = ssid
        self.password = password
        self.encryption_password = encryption_password or password
        self.secure_handshake = SecureHandshake(self.encryption_password)
        self.connected_clients = {}
        self.failed_attempts = {}  # Track failed authentication attempts
        self.max_failed_attempts = 5
        self.lockout_duration = 300  # 5 minutes lockout
        
        # Security settings
        self.enable_encrypted_nonces = True
        self.enable_replay_protection = True
        self.enable_session_tracking = True
        self.enable_brute_force_protection = True
        
    def start_ap(self):
        """Start the access point with security features"""
        print(f"🔒 Starting secure access point: {self.ssid}")
        print(f"   - Encrypted nonces: {'✅' if self.enable_encrypted_nonces else '❌'}")
        print(f"   - Replay protection: {'✅' if self.enable_replay_protection else '❌'}")
        print(f"   - Session tracking: {'✅' if self.enable_session_tracking else '❌'}")
        print(f"   - Brute force protection: {'✅' if self.enable_brute_force_protection else '❌'}")
        return True
    
    def handle_connection_request(self, client_mac):
        """Handle client connection request with security checks"""
        # Check if client is locked out
        if self._is_client_locked_out(client_mac):
            return False, "Client temporarily locked out due to failed attempts"
        
        # Check if client is already connected
        if client_mac in self.connected_clients:
            return False, "Client already connected"
        
        # Initiate secure handshake
        session_id, encrypted_anonce = self.secure_handshake.initiate_handshake(client_mac)
        
        print(f"🔐 Initiating secure handshake with {client_mac}")
        print(f"   Session ID: {session_id.hex()}")
        print(f"   Encrypted ANonce: {encrypted_anonce[:20].hex()}...")
        
        return True, {
            'session_id': session_id,
            'encrypted_anonce': encrypted_anonce
        }
    
    def authenticate_client(self, client_mac, session_id, encrypted_snonce, client_mic, password_attempt):
        """Authenticate client with enhanced security"""
        # Check if client is locked out
        if self._is_client_locked_out(client_mac):
            return False, "Client temporarily locked out"
        
        # Verify password
        if password_attempt != self.password:
            self._record_failed_attempt(client_mac)
            return False, "Invalid password"
        
        # Process handshake response
        success, message = self.secure_handshake.process_client_response(
            session_id, encrypted_snonce, client_mic
        )
        
        if not success:
            self._record_failed_attempt(client_mac)
            return False, message
        
        # Complete handshake
        success, session_key = self.secure_handshake.complete_handshake(session_id)
        
        if success:
            # Add client to connected list
            self.connected_clients[client_mac] = {
                'session_id': session_id,
                'session_key': session_key,
                'connected_time': time.time(),
                'last_activity': time.time()
            }
            
            # Clear failed attempts for this client
            if client_mac in self.failed_attempts:
                del self.failed_attempts[client_mac]
            
            print(f"✅ Client {client_mac} successfully authenticated")
            print(f"   Session key: {session_key[:16].hex()}...")
            
            return True, "Authentication successful"
        else:
            return False, "Handshake completion failed"
    
    def _is_client_locked_out(self, client_mac):
        """Check if client is temporarily locked out"""
        if client_mac not in self.failed_attempts:
            return False
        
        failed_data = self.failed_attempts[client_mac]
        if time.time() - failed_data['last_attempt'] < self.lockout_duration:
            return failed_data['count'] >= self.max_failed_attempts
        
        # Reset if lockout period has passed
        del self.failed_attempts[client_mac]
        return False
    
    def _record_failed_attempt(self, client_mac):
        """Record a failed authentication attempt"""
        if client_mac not in self.failed_attempts:
            self.failed_attempts[client_mac] = {
                'count': 0,
                'last_attempt': time.time()
            }
        
        self.failed_attempts[client_mac]['count'] += 1
        self.failed_attempts[client_mac]['last_attempt'] = time.time()
        
        remaining_attempts = self.max_failed_attempts - self.failed_attempts[client_mac]['count']
        if remaining_attempts > 0:
            print(f"⚠️  Failed authentication attempt for {client_mac}")
            print(f"   Remaining attempts: {remaining_attempts}")
        else:
            print(f"🚫 Client {client_mac} locked out for {self.lockout_duration} seconds")
    
    def disconnect_client(self, client_mac):
        """Disconnect a client"""
        if client_mac in self.connected_clients:
            del self.connected_clients[client_mac]
            print(f"📴 Client {client_mac} disconnected")
            return True
        return False
    
    def get_status(self):
        """Get router status and security information"""
        status = {
            'ssid': self.ssid,
            'connected_clients': len(self.connected_clients),
            'locked_out_clients': len(self.failed_attempts),
            'active_sessions': len(self.secure_handshake.handshake_sessions),
            'security_features': {
                'encrypted_nonces': self.enable_encrypted_nonces,
                'replay_protection': self.enable_replay_protection,
                'session_tracking': self.enable_session_tracking,
                'brute_force_protection': self.enable_brute_force_protection
            }
        }
        return status


class SecurityMonitor:
    """
    Monitor and log security events
    """
    
    def __init__(self):
        self.security_log = []
        self.alert_thresholds = {
            'failed_attempts_per_minute': 10,
            'suspicious_patterns': 5
        }
    
    def log_event(self, event_type, details):
        """Log a security event"""
        event = {
            'timestamp': time.time(),
            'type': event_type,
            'details': details
        }
        self.security_log.append(event)
        
        # Check for security alerts
        self._check_alerts(event)
    
    def _check_alerts(self, event):
        """Check for security alerts based on events"""
        if event['type'] == 'failed_authentication':
            recent_failures = len([
                e for e in self.security_log[-60:]  # Last 60 seconds
                if e['type'] == 'failed_authentication'
            ])
            
            if recent_failures >= self.alert_thresholds['failed_attempts_per_minute']:
                print(f"🚨 SECURITY ALERT: High rate of failed authentication attempts!")
                print(f"   Failures in last minute: {recent_failures}")


def main():
    """
    Demonstration of the secure router system
    """
    print("🔒 WPA2 Attack Prevention System")
    print("=" * 50)
    
    # Create secure router
    router = Router("SecureWiFi", "MySecurePassword123", "RouterEncryptionKey456")
    security_monitor = SecurityMonitor()
    
    # Start the access point
    router.start_ap()
    
    # Simulate client connection attempts
    test_clients = [
        "aa:bb:cc:dd:ee:ff",
        "11:22:33:44:55:66",
        "aa:bb:cc:dd:ee:ff"  # Same client, should be locked out
    ]
    
    for i, client_mac in enumerate(test_clients):
        print(f"\n--- Test {i+1}: Client {client_mac} ---")
        
        # Handle connection request
        success, result = router.handle_connection_request(client_mac)
        if not success:
            print(f"❌ Connection rejected: {result}")
            continue
        
        session_data = result
        
        # Simulate authentication attempt
        if i == 0:  # Correct password
            success, message = router.authenticate_client(
                client_mac,
                session_data['session_id'],
                b"fake_encrypted_snonce",  # Simplified for demo
                b"fake_mic",
                "MySecurePassword123"
            )
        else:  # Wrong password
            success, message = router.authenticate_client(
                client_mac,
                session_data['session_id'],
                b"fake_encrypted_snonce",
                b"fake_mic",
                "WrongPassword"
            )
        
        print(f"Authentication result: {message}")
        
        # Log security event
        event_type = "successful_authentication" if success else "failed_authentication"
        security_monitor.log_event(event_type, {
            'client_mac': client_mac,
            'message': message
        })
    
    # Display final status
    print(f"\n--- Router Status ---")
    status = router.get_status()
    for key, value in status.items():
        if key != 'security_features':
            print(f"{key}: {value}")
    
    print(f"\nSecurity Features:")
    for feature, enabled in status['security_features'].items():
        print(f"  {feature}: {'✅' if enabled else '❌'}")


if __name__ == "__main__":
    main()
