# utils/generate_demo_data.py - NEW FILE NEEDED
"""
Generate realistic demo data for sandbox testing
"""
class GenerateDemoData:
    def create_sample_products(self, company_name: str) -> list:
        """Create sample products for demo"""
        products = [
            {
                'serial_number': 'DEMO001ABC123',
                'brand': company_name.split()[0] if company_name.split() else 'DemoTech',
                'model': 'Pro-X1',
                'device_type': 'smartphone',
                'authentic': True,
                'description': 'Premium smartphone with advanced verification'
            },
            {
                'serial_number': 'DEMO002XYZ789', 
                'brand': company_name.split()[0] if company_name.split() else 'DemoTech',
                'model': 'Ultra-M2',
                'device_type': 'tablet',
                'authentic': True,
                'description': 'High-performance tablet'
            },
            {
                'serial_number': 'FAKE123COUNTERFEIT',
                'brand': 'Unknown',
                'model': 'Fake-Copy',
                'device_type': 'smartphone',
                'authentic': False,
                'description': 'This is a counterfeit product for demo purposes'
            },
            {
                'serial_number': 'DEMO003DEF456',
                'brand': company_name.split()[0] if company_name.split() else 'DemoTech',
                'model': 'Watch-S1',
                'device_type': 'smartwatch',
                'authentic': True,
                'description': 'Smart fitness watch'
            }
        ]
        return products

generate_demo_data = GenerateDemoData()
