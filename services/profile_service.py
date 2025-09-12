from utils.helper_functions import (
     is_valid_email, get_primary_email, email_exists_globally, 
     is_valid_email, wallet_exists_globally, is_valid_wallet_address, get_current_company_name
)

class ProfileUpdateValidator:
    """Centralized validation for profile updates"""
    
    @staticmethod
    def validate_email_operation(operation, email, user, current_user_id):
        """Validate email operations"""
        if not email or not email.strip():
            return "Email address is required"
        
        email = email.strip().lower()
        
        if not is_valid_email(email):
            return "Invalid email format"
        
        current_emails = user.get('emails', [])
        primary_email = get_primary_email(user)
        
        if operation == 'add':
            if email in current_emails:
                return "Email already exists"
            if email_exists_globally(email, current_user_id):
                return "Email is already registered to another account"
                
        elif operation == 'remove':
            if email == primary_email:
                return "Cannot remove primary email"
            if email not in current_emails:
                return "Email not found"
                
        elif operation == 'set_primary':
            if email not in current_emails:
                return "Email not found in your account"
        
        return None
    
    @staticmethod
    def validate_wallet_operation(operation, wallet_address, user, current_user_id):
        """Validate wallet operations"""
        if not wallet_address or not wallet_address.strip():
            return "Wallet address is required"
        
        wallet_address = wallet_address.strip()
        
        if not is_valid_wallet_address(wallet_address):
            return "Invalid wallet address format"
        
        current_wallets = user.get('wallet_addresses', [])
        verified_wallets = user.get('verified_wallets', [])
        
        if operation == 'add':
            if wallet_address in current_wallets:
                return "Wallet already exists"
            if wallet_exists_globally(wallet_address, current_user_id):
                return "Wallet is already registered to another account"
                
        elif operation == 'remove':
            if wallet_address not in current_wallets:
                return "Wallet not found"
                
        elif operation == 'set_primary':
            if wallet_address not in current_wallets:
                return "Wallet not found in your account"
            if wallet_address not in verified_wallets:
                return "Wallet must be verified before setting as primary"
        
        return None
    
    @staticmethod
    def validate_company_update(company_name, user):
        """Validate company name update"""
        if not company_name or not company_name.strip():
            return "Company name is required"
        
        company_name = company_name.strip()
        
        if len(company_name) < 2:
            return "Company name must be at least 2 characters"
        
        if len(company_name) > 100:
            return "Company name must be less than 100 characters"
        
        current_company = get_current_company_name(user)
        if company_name == current_company:
            return "New company name must be different from current name"
        
        return None

class ProfileUpdateHandler:
    """Handle different types of profile updates"""
    
    @staticmethod
    def handle_email_operations(operations, user, current_user_id):
        """Process all email operations"""
        updates = {}
        current_emails = user.get('emails', [])
        primary_email = user.get('primary_email')
        
        for op in operations:
            operation = op.get('operation')
            email = op.get('email', '').strip().lower()
            
            # Validate operation
            error = ProfileUpdateValidator.validate_email_operation(
                operation, email, user, current_user_id
            )
            if error:
                raise ValueError(f"Email {operation}: {error}")
            
            # Apply operation
            if operation == 'add':
                if email not in current_emails:
                    current_emails.append(email)
                    
            elif operation == 'remove':
                current_emails = [e for e in current_emails if e != email]
                # If removing primary, set new primary
                if email == primary_email and current_emails:
                    primary_email = current_emails[0]
                    
            elif operation == 'set_primary':
                primary_email = email
        
        updates['emails'] = current_emails
        if primary_email:
            updates['primary_email'] = primary_email
        
        return updates
    
    @staticmethod
    def handle_wallet_operations(operations, user, current_user_id):
        """Process all wallet operations"""
        updates = {}
        current_wallets = user.get('wallet_addresses', [])
        primary_wallet = user.get('primary_wallet')
        
        for op in operations:
            operation = op.get('operation')
            wallet_address = op.get('wallet_address', '').strip()
            
            # Validate operation
            error = ProfileUpdateValidator.validate_wallet_operation(
                operation, wallet_address, user, current_user_id
            )
            if error:
                raise ValueError(f"Wallet {operation}: {error}")
            
            # Apply operation
            if operation == 'add':
                if wallet_address not in current_wallets:
                    current_wallets.append(wallet_address)
                    # Set as primary if first wallet
                    if not primary_wallet:
                        primary_wallet = wallet_address
                        
            elif operation == 'remove':
                current_wallets = [w for w in current_wallets if w != wallet_address]
                # If removing primary, set new primary
                if wallet_address == primary_wallet and current_wallets:
                    # Find first verified wallet or just first wallet
                    verified_wallets = user.get('verified_wallets', [])
                    for wallet in current_wallets:
                        if wallet in verified_wallets:
                            primary_wallet = wallet
                            break
                    else:
                        primary_wallet = current_wallets[0] if current_wallets else None
                        
            elif operation == 'set_primary':
                primary_wallet = wallet_address
        
        updates['wallet_addresses'] = current_wallets
        if primary_wallet:
            updates['primary_wallet'] = primary_wallet
        
        return updates
    
    @staticmethod
    def handle_company_update(company_name, user):
        """Process company name update"""
        error = ProfileUpdateValidator.validate_company_update(company_name, user)
        if error:
            raise ValueError(f"Company update: {error}")
        
        company_name = company_name.strip()
        current_company_names = user.get('company_names', [])
        
        # Add to history if not already present
        updated_company_names = current_company_names
        if company_name not in current_company_names:
            updated_company_names = current_company_names + [company_name]
        
        return {
            'company_names': updated_company_names,
            'current_company_name': company_name
        }

