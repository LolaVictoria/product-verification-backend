# services/verification_service.py
from datetime import datetime, timezone
from bson import ObjectId
from typing import Dict, List, Optional

from utils.database import get_db_connection
from services.blockchain_service import blockchain_service

class VerificationService:
    """Service for handling product verification operations"""
    
    def __init__(self):
        pass
    
    def verify_product(self, serial_number: str, customer_id: str = None, 
                      user_role: str = None, user_ip: str = None) -> Dict:
        """Verify product authenticity"""
        try:
            db = get_db_connection()
            
            # Database lookup
            product = db.products.find_one({"serial_number": serial_number})
            verification_id = None
            
            if product:
                if product.get("blockchain_verified"):
                    # Try blockchain verification
                    try:
                        blockchain_result = blockchain_service.verify_product_on_blockchain(serial_number)
                    except Exception as e:
                        blockchain_result = {"verified": False, "error": str(e)}
                    
                    if not blockchain_result.get("verified"):
                        result = {
                            "authentic": False,
                            "message": "Product found in database but blockchain verification failed",
                            "source": "database_only",
                            "blockchain_error": blockchain_result.get("error"),
                            "serialNumber": serial_number,
                            "brand": product.get("brand"),
                            "model": product.get("model"),
                            "deviceType": product.get("device_type"),
                            "manufacturerName": product.get("manufacturer_name")
                        }
                    else:
                        result = self._format_authentic_result(product, blockchain_result, "blockchain")
                else:
                    result = self._format_authentic_result(product, None, "database")
            else:
                # Check blockchain directly
                try:
                    blockchain_result = blockchain_service.verify_product_on_blockchain(serial_number)
                except Exception as e:
                    blockchain_result = {"verified": False, "error": str(e)}
                
                if blockchain_result.get("verified"):
                    result = self._format_blockchain_only_result(serial_number, blockchain_result)
                else:
                    result = self._format_not_found_result(serial_number)
            
            # Log verification attempt
            verification_id = self._log_verification(
                serial_number=serial_number,
                customer_id=customer_id,
                product=product,
                result=result,
                user_role=user_role,
                user_ip=user_ip
            )
            
            if verification_id:
                result["verificationId"] = verification_id
            
            return result
            
        except Exception as e:
            raise Exception(f"Verification service error: {str(e)}")
    
    def verify_batch(self, serial_numbers: List[str], customer_id: str = None,
                    user_role: str = None, user_ip: str = None) -> Dict:
        """Verify multiple products in batch"""
        try:
            if not serial_numbers or len(serial_numbers) > 10:
                raise ValueError("Please provide 1-10 serial numbers")
            
            results = []
            total_verified = 0
            
            for serial_number in serial_numbers:
                result = self.verify_product(
                    serial_number=serial_number,
                    customer_id=customer_id,
                    user_role=user_role,
                    user_ip=user_ip
                )
                
                if result.get("authentic"):
                    total_verified += 1
                    
                results.append({
                    "serialNumber": serial_number,
                    "authentic": result.get("authentic", False),
                    "brand": result.get("brand"),
                    "model": result.get("model"),
                    "deviceType": result.get("deviceType"),
                    "manufacturerName": result.get("manufacturerName"),
                    "source": result.get("source"),
                    "message": result.get("message", "")
                })
            
            return {
                "status": "success",
                "results": results,
                "total_verified": total_verified,
                "total_checked": len(results)
            }
            
        except Exception as e:
            raise Exception(f"Batch verification failed: {str(e)}")
    
    def get_device_details(self, serial_number: str) -> Optional[Dict]:
        """Get detailed device information"""
        try:
            db = get_db_connection()
            product = db.products.find_one({"serial_number": serial_number})
            
            if product:
                return {
                    "serial_number": product.get("serial_number"),
                    "serialNumber": product.get("serial_number"),
                    "brand": product.get("brand"),
                    "model": product.get("model"),
                    "device_type": product.get("device_type"),
                    "deviceType": product.get("device_type"),
                    "storage_data": product.get("storage_data"),
                    "storage": product.get("storage_data"),
                    "color": product.get("color"),
                    "manufacturer_name": product.get("manufacturer_name"),
                    "manufacturerName": product.get("manufacturer_name"),
                    "registration_type": product.get("registration_type"),
                    "blockchain_verified": product.get("blockchain_verified", False),
                    "transaction_hash": product.get("transaction_hash"),
                    "registered_at": product.get("registered_at"),
                    "created_at": product.get("created_at")
                }
            
            return None
                
        except Exception as e:
            raise Exception(f"Could not load device details: {str(e)}")
    
    def get_ownership_history(self, serial_number: str) -> List[Dict]:
        """Get ownership history for a verified product"""
        try:
            db = get_db_connection()
            product = db.products.find_one({"serial_number": serial_number})
            
            if not product:
                raise ValueError("Product not found")

            ownership_history = product.get("ownership_history", [])
            
            history_data = []
            for transfer in ownership_history:
                history_data.append({
                    "transfer_reason": transfer.get("notes", "Initial Registration"),
                    "from": transfer.get("previous_owner", "Manufacturer"),
                    "to": transfer.get("owner_name"),
                    "transfer_date": transfer.get("transfer_date", product.get("registered_at")),
                    "sale_price": transfer.get("sale_price", 0),
                    "transaction_hash": transfer.get("transaction_hash", product.get("transaction_hash"))
                })

            # If no ownership history exists, create default entry
            if not history_data:
                history_data.append({
                    "transfer_reason": "Initial Registration",
                    "previous_owner": "Manufacturer",
                    "new_owner": product.get("current_owner", product.get("manufacturer_wallet")),
                    "transfer_date": product.get("registered_at"),
                    "sale_price": 0,
                    "transaction_hash": product.get("transaction_hash")
                })

            return history_data

        except Exception as e:
            raise Exception(f"Could not load ownership history: {str(e)}")
    
    def create_counterfeit_report(self, customer_id: str, report_data: Dict) -> str:
        """Create a counterfeit report"""
        try:
            db = get_db_connection()
            
            serial_number = report_data.get('serial_number')
            product_name = report_data.get('product_name')
            device_category = report_data.get('device_category')
            customer_consent = report_data.get('customer_consent', False)
            location_data = report_data.get('location_data') if customer_consent else None
            
            # Find the most recent verification
            verification = db.verifications.find_one({
                'serial_number': serial_number,
                'customer_id': ObjectId(customer_id)
            }, sort=[('created_at', -1)])
            
            if not verification:
                raise ValueError('Verification not found')

            # Update the verification log with device info
            try:
                verification_update = {
                    'device_name': product_name,
                    'device_category': device_category,
                    'updated_at': datetime.now(timezone.utc)
                }
                
                # Extract brand from product name if possible
                if product_name:
                    brand_guess = product_name.split()[0] if product_name.split() else 'Unknown'
                    verification_update['brand'] = brand_guess
                
                db.verifications.update_one(
                    {'_id': verification['_id']},
                    {'$set': verification_update}
                )
                
            except Exception as update_error:
                pass  # Non-critical operation

            # Create the counterfeit report
            report_doc = {
                'verification_id': verification['_id'],
                'product_id': verification.get('product_id'), 
                'manufacturer_id': verification.get('manufacturer_id'),  
                'customer_id': ObjectId(customer_id),
                'serial_number': serial_number,
                'product_name': product_name,  
                'device_category': device_category,
                'customer_consent': customer_consent,
                'report_status': 'pending',
                'created_at': datetime.now(timezone.utc)
            }
            
            if customer_consent and location_data:
                report_doc.update({
                    'store_name': location_data.get('store_name'),
                    'store_address': location_data.get('store_address'),
                    'city': location_data.get('city'),
                    'state': location_data.get('state'),
                    'purchase_date': datetime.strptime(location_data.get('purchase_date'), '%Y-%m-%d') if location_data.get('purchase_date') else None,
                    'purchase_price': float(location_data.get('purchase_price', 0)) if location_data.get('purchase_price') else None,
                    'additional_notes': location_data.get('additional_notes')
                })
            
            result = db.counterfeit_reports.insert_one(report_doc)
            return str(result.inserted_id)
            
        except Exception as e:
            raise Exception(f"Failed to create counterfeit report: {str(e)}")
    
    def get_system_stats(self) -> Dict:
        """Get system-wide statistics"""
        try:
            db = get_db_connection()
            
            # Count total products
            total_devices = db.products.count_documents({})
            blockchain_devices = db.products.count_documents({"blockchain_verified": True})
            
            # Count verification logs
            total_verifications = db.verifications.count_documents({})
            
            # Calculate authenticity rate
            authentic_verifications = db.verifications.count_documents({"is_authentic": True})
            authenticity_rate = int((authentic_verifications / total_verifications * 100)) if total_verifications > 0 else 0
            
            return {
                "total_devices": total_devices,
                "blockchain_devices": blockchain_devices,
                "total_verifications": total_verifications,
                "authenticity_rate": authenticity_rate
            }
            
        except Exception:
            return {
                "total_devices": 0,
                "blockchain_devices": 0,
                "total_verifications": 0,
                "authenticity_rate": 0
            }
    
    def _format_authentic_result(self, product: Dict, blockchain_result: Dict = None, source: str = "database") -> Dict:
        """Format authentic verification result"""
        result = {
            "authentic": True,
            "serialNumber": product.get("serial_number"),
            "brand": product.get("brand"),
            "model": product.get("model"),
            "deviceType": product.get("device_type"),
            "color": product.get("color"),
            "storage": product.get("storage_data"),
            "manufacturerName": product.get("manufacturer_name"),
            "source": source,
            "blockchain_verified": bool(blockchain_result),
            "ownership_history": product.get("ownership_history", []),
            "registered_at": product.get("registered_at"),
            "created_at": product.get("created_at"),
            "verification_timestamp": datetime.now(timezone.utc)
        }
        
        if blockchain_result:
            result["message"] = "Product verified on blockchain"
            result["blockchain_proof"] = blockchain_result.get("proof")
        else:
            result["message"] = "Product verified in database only"
            
        return result
    
    def _format_blockchain_only_result(self, serial_number: str, blockchain_result: Dict) -> Dict:
        """Format blockchain-only verification result"""
        tx_hash = blockchain_result.get("transaction_hash")
        contract_address = blockchain_result.get("contract_address")
        network = blockchain_result.get("network", "sepolia")

        explorer_urls = {
            "ethereum": "https://etherscan.io",
            "sepolia": "https://sepolia.etherscan.io",
            "polygon": "https://polygonscan.com", 
            "bsc": "https://bscscan.com"
        }
        
        base_url = explorer_urls.get(network, "https://sepolia.etherscan.io")

        return {
            "authentic": True,
            "serialNumber": serial_number,
            "source": "blockchain",
            "blockchain_verified": True,
            "message": "Product verified on blockchain",
            "blockchain_proof": {
                "transaction_hash": tx_hash,
                "contract_address": contract_address or "0x07c05F17f53ff83d0b5F469bFA0Cb36bDc9eA950",
                "network": network,
                "explorer_links": {
                    "transaction": f"{base_url}/tx/{tx_hash}" if tx_hash else None,
                    "contract": f"{base_url}/address/{contract_address or '0x07c05F17f53ff83d0b5F469bFA0Cb36bDc9eA950'}"
                }
            },
            "verification_timestamp": datetime.now(timezone.utc).isoformat(),
            "brand": "Unknown",
            "model": "Unknown", 
            "deviceType": "Unknown"
        }
    
    def _format_not_found_result(self, serial_number: str) -> Dict:
        """Format not found verification result"""
        return {
            "authentic": False,
            "message": "Product not found in database or blockchain",
            "source": "not_found",
            "serialNumber": serial_number,
            "brand": "Unknown",
            "model": "Unknown",
            "deviceType": "Unknown"
        }
    
    def _log_verification(self, serial_number: str, customer_id: str, product: Dict,
                         result: Dict, user_role: str = None, user_ip: str = None) -> Optional[str]:
        """Log verification attempt"""
        try:
            db = get_db_connection()
            
            verification_doc = {
                "serial_number": serial_number,
                "customer_id": ObjectId(customer_id) if customer_id else None,
                "product_id": product['_id'] if product else None,
                "manufacturer_id": product['manufacturer_id'] if product else None,
                "is_authentic": result["authentic"],
                "source": result["source"],
                "user_id": customer_id,
                "user_role": user_role,
                "user_ip": user_ip,
                "confidence_score": result.get("confidence_score", 85.0 if result["authentic"] else 15.0),
                "response_time": 0.5,
                "verification_method": "manual",
                "transaction_success": result["authentic"],
                "device_name": f"{result.get('brand', 'Unknown')} {result.get('model', 'Unknown')}".strip(),
                "device_category": result.get('deviceType', 'Unknown'),
                "brand": result.get('brand', 'Unknown'),
                "timestamp": datetime.now(timezone.utc),
                "created_at": datetime.now(timezone.utc),
                "updated_at": datetime.now(timezone.utc)
            }
            
            verification_result = db.verifications.insert_one(verification_doc)
            return str(verification_result.inserted_id)
            
        except Exception:
            return None

# Singleton instance
verification_service = VerificationService()