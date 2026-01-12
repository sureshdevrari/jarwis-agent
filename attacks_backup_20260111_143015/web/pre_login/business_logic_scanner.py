"""
Jarwis AGI Pen Test - Business Logic Vulnerability Scanner
Detects Business Logic flaws (A04:2021 - Insecure Design)
Based on Web Hacking 101 techniques - adapted for 2025
"""

import asyncio
import logging
import re
import json
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from urllib.parse import urlparse, urljoin, parse_qs, urlencode
import aiohttp
import ssl

logger = logging.getLogger(__name__)


@dataclass
class ScanResult:
    id: str
    category: str
    severity: str
    title: str
    description: str
    url: str
    method: str
    parameter: str = ""
    evidence: str = ""
    remediation: str = ""
    cwe_id: str = ""
    poc: str = ""
    reasoning: str = ""
    request_data: str = ""
    response_data: str = ""


class BusinessLogicScanner:
    """
    Scans for Business Logic vulnerabilities
    OWASP A04:2021 - Insecure Design
    
    Attack vectors:
    - Negative value manipulation (prices, quantities)
    - Price tampering
    - Workflow bypass
    - Parameter tampering
    - Hidden field manipulation
    - Trust boundary violations
    - Privilege escalation via parameters
    - Cart manipulation
    - Payment bypass
    """
    
    # Numeric parameters to test
    NUMERIC_PARAMS = [
        'price', 'amount', 'quantity', 'qty', 'count', 'total', 'subtotal',
        'discount', 'tax', 'fee', 'balance', 'credit', 'points', 'reward',
        'limit', 'max', 'min', 'rate', 'percent', 'percentage', 'value'
    ]
    
    # Status/role parameters to test
    STATUS_PARAMS = [
        'role', 'admin', 'is_admin', 'isAdmin', 'user_type', 'userType',
        'access_level', 'accessLevel', 'permission', 'level', 'tier',
        'status', 'verified', 'premium', 'vip', 'is_verified', 'approved'
    ]
    
    # Payment/order related endpoints
    PAYMENT_ENDPOINTS = [
        '/checkout', '/payment', '/pay', '/order', '/cart', '/purchase',
        '/api/checkout', '/api/payment', '/api/order', '/api/cart',
        '/api/purchase', '/process-payment', '/confirm-order'
    ]
    
    def __init__(self, config: dict, context):
        self.config = config
        self.context = context
        self.results: List[ScanResult] = []
        self.rate_limit = config.get('rate_limit', 10)
        self.timeout = config.get('timeout', 15)
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
        
    async def scan(self) -> List[ScanResult]:
        """Main scan method"""
        logger.info("Starting Business Logic scan...")
        self.results = []
        
        base_url = self.config.get('target', {}).get('url', '')
        if not base_url:
            base_url = self.config.get('target_url', '')
        
        if not base_url:
            return self.results
        
        connector = aiohttp.TCPConnector(ssl=self.ssl_context, limit=10)
        
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=self.timeout)
        ) as session:
            
            # Test payment endpoints
            for endpoint in self.PAYMENT_ENDPOINTS:
                url = urljoin(base_url, endpoint)
                await self._test_price_manipulation(session, url)
                await self._test_quantity_manipulation(session, url)
            
            # Test discovered endpoints
            if hasattr(self.context, 'endpoints'):
                for endpoint in self.context.endpoints[:30]:
                    ep_url = endpoint.get('url', '') if isinstance(endpoint, dict) else str(endpoint)
                    method = endpoint.get('method', 'GET') if isinstance(endpoint, dict) else 'GET'
                    params = endpoint.get('params', {}) if isinstance(endpoint, dict) else {}
                    
                    if ep_url:
                        await self._test_parameter_tampering(session, ep_url, method, params)
                        await self._test_privilege_escalation(session, ep_url, method)
        
        logger.info(f"Business logic scan complete. Found {len(self.results)} vulnerabilities")
        return self.results
    
    async def _test_price_manipulation(self, session: aiohttp.ClientSession, url: str):
        """Test for price manipulation vulnerabilities"""
        headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'Mozilla/5.0'
        }
        
        # Test payloads with manipulated prices
        test_payloads = [
            # Negative prices
            {'price': -100, 'product_id': 1, 'quantity': 1},
            {'amount': -50, 'item_id': 1},
            {'total': -1, 'order_id': 1},
            
            # Zero prices
            {'price': 0, 'product_id': 1, 'quantity': 1},
            {'amount': 0.00, 'item_id': 1},
            
            # Very small prices
            {'price': 0.01, 'product_id': 1, 'quantity': 1},
            {'price': 0.001, 'product_id': 1},
            
            # Price as string
            {'price': 'free', 'product_id': 1},
            {'price': 'null', 'product_id': 1},
            
            # Large discounts
            {'discount': 100, 'product_id': 1},
            {'discount': 150, 'product_id': 1},
            {'discount_percent': 100, 'product_id': 1},
            
            # Float manipulation
            {'price': 0.0000001, 'product_id': 1},
            {'price': 1e-10, 'product_id': 1},
        ]
        
        for payload in test_payloads:
            try:
                await asyncio.sleep(1 / self.rate_limit)
                
                async with session.post(url, json=payload, headers=headers) as response:
                    if response.status in [200, 201]:
                        body = await response.text()
                        
                        # Check for success indicators
                        success_indicators = ['success', 'order_id', 'confirmed', 'processed', 'created']
                        if any(s in body.lower() for s in success_indicators):
                            # Check what price was actually applied
                            price_param = next((k for k in payload.keys() if k in ['price', 'amount', 'total', 'discount']), None)
                            
                            if price_param and (payload[price_param] < 0 or payload[price_param] == 0):
                                result = ScanResult(
                                    id=f"BIZLOGIC-PRICE-{len(self.results)+1}",
                                    category="A04:2021 - Insecure Design",
                                    severity="critical",
                                    title="Price Manipulation Vulnerability",
                                    description=f"Server accepted negative/zero value for {price_param}. Financial fraud possible.",
                                    url=url,
                                    method="POST",
                                    parameter=price_param,
                                    evidence=f"{price_param}={payload[price_param]} was accepted",
                                    remediation="Validate all financial values server-side. Reject negative and zero amounts.",
                                    cwe_id="CWE-20",
                                    poc=json.dumps(payload),
                                    reasoning="Negative/zero price was processed successfully"
                                )
                                self.results.append(result)
                                return
                                
            except Exception as e:
                logger.debug(f"Price manipulation test error: {e}")
    
    async def _test_quantity_manipulation(self, session: aiohttp.ClientSession, url: str):
        """Test for quantity manipulation vulnerabilities"""
        headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'Mozilla/5.0'
        }
        
        test_payloads = [
            # Negative quantities
            {'quantity': -1, 'product_id': 1},
            {'qty': -10, 'item_id': 1},
            {'count': -5, 'product_id': 1},
            
            # Extremely large quantities
            {'quantity': 999999999, 'product_id': 1},
            {'qty': 2147483647, 'item_id': 1},  # Integer max
            
            # Fractional quantities
            {'quantity': 0.5, 'product_id': 1},
            {'quantity': 0.001, 'product_id': 1},
            
            # Zero quantity
            {'quantity': 0, 'product_id': 1, 'price': 100},
        ]
        
        for payload in test_payloads:
            try:
                await asyncio.sleep(1 / self.rate_limit)
                
                async with session.post(url, json=payload, headers=headers) as response:
                    if response.status in [200, 201]:
                        body = await response.text()
                        
                        if 'success' in body.lower() or 'order' in body.lower():
                            qty_param = next((k for k in payload.keys() if k in ['quantity', 'qty', 'count']), None)
                            
                            if qty_param and payload[qty_param] < 0:
                                result = ScanResult(
                                    id=f"BIZLOGIC-QTY-{len(self.results)+1}",
                                    category="A04:2021 - Insecure Design",
                                    severity="high",
                                    title="Quantity Manipulation Vulnerability",
                                    description=f"Server accepted negative quantity ({payload[qty_param]}). May affect inventory or billing.",
                                    url=url,
                                    method="POST",
                                    parameter=qty_param,
                                    evidence=f"{qty_param}={payload[qty_param]} was accepted",
                                    remediation="Validate quantities are positive integers within expected range.",
                                    cwe_id="CWE-20",
                                    poc=json.dumps(payload),
                                    reasoning="Negative quantity processed successfully"
                                )
                                self.results.append(result)
                                return
                                
            except Exception as e:
                logger.debug(f"Quantity test error: {e}")
    
    async def _test_parameter_tampering(self, session: aiohttp.ClientSession, 
                                        url: str, method: str, params: dict):
        """Test for parameter tampering vulnerabilities"""
        headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'Mozilla/5.0'
        }
        
        # Test adding hidden parameters
        hidden_params = [
            {'is_free': True},
            {'bypass_payment': True},
            {'skip_validation': True},
            {'debug': True},
            {'test_mode': True},
            {'admin_override': True},
            {'force': True},
            {'approved': True},
        ]
        
        for hidden in hidden_params:
            try:
                await asyncio.sleep(1 / self.rate_limit)
                
                test_params = {**params, **hidden}
                
                if method == 'POST':
                    async with session.post(url, json=test_params, headers=headers) as response:
                        body = await response.text()
                        
                        if response.status == 200 and 'success' in body.lower():
                            param_name = list(hidden.keys())[0]
                            
                            result = ScanResult(
                                id=f"BIZLOGIC-PARAM-{len(self.results)+1}",
                                category="A04:2021 - Insecure Design",
                                severity="high",
                                title=f"Hidden Parameter Accepted: {param_name}",
                                description=f"Server accepts hidden parameter '{param_name}' which may bypass security checks.",
                                url=url,
                                method=method,
                                parameter=param_name,
                                evidence=f"Added {param_name}={hidden[param_name]}",
                                remediation="Whitelist allowed parameters. Ignore unexpected parameters.",
                                cwe_id="CWE-639",
                                poc=json.dumps(test_params),
                                reasoning="Hidden parameter was processed by server"
                            )
                            self.results.append(result)
                            return
                            
            except Exception as e:
                logger.debug(f"Parameter tampering test error: {e}")
    
    async def _test_privilege_escalation(self, session: aiohttp.ClientSession, url: str, method: str):
        """Test for privilege escalation via parameters"""
        headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'Mozilla/5.0'
        }
        
        # Test role escalation payloads
        escalation_payloads = [
            {'role': 'admin'},
            {'role': 'administrator'},
            {'is_admin': True},
            {'isAdmin': True},
            {'admin': True},
            {'user_type': 'admin'},
            {'userType': 'admin'},
            {'access_level': 'admin'},
            {'accessLevel': 999},
            {'permission': 'all'},
            {'permissions': ['admin', 'superuser']},
            {'group': 'administrators'},
            {'tier': 'premium'},
            {'verified': True},
            {'approved': True},
        ]
        
        for payload in escalation_payloads:
            try:
                await asyncio.sleep(1 / self.rate_limit)
                
                if method == 'POST':
                    async with session.post(url, json=payload, headers=headers) as response:
                        body = await response.text()
                        
                        if response.status == 200:
                            # Check for indicators that escalation worked
                            admin_indicators = ['admin', 'dashboard', 'manage', 'settings', 'configuration']
                            if any(ind in body.lower() for ind in admin_indicators):
                                param_name = list(payload.keys())[0]
                                
                                result = ScanResult(
                                    id=f"BIZLOGIC-PRIV-{len(self.results)+1}",
                                    category="A01:2021 - Broken Access Control",
                                    severity="critical",
                                    title="Privilege Escalation via Parameter",
                                    description=f"Setting '{param_name}' may grant elevated privileges.",
                                    url=url,
                                    method=method,
                                    parameter=param_name,
                                    evidence=f"Response contains admin-related content",
                                    remediation="Never trust client-provided role/permission values. Enforce RBAC server-side.",
                                    cwe_id="CWE-269",
                                    poc=json.dumps(payload),
                                    reasoning="Role/admin parameter may have been accepted"
                                )
                                self.results.append(result)
                                return
                                
            except Exception as e:
                logger.debug(f"Privilege escalation test error: {e}")


class WorkflowBypassScanner:
    """
    Scans for Workflow/Process Bypass vulnerabilities
    OWASP A04:2021 - Insecure Design
    
    Attack vectors:
    - Step skipping
    - Direct object access
    - Status manipulation
    - Verification bypass
    """
    
    def __init__(self, config: dict, context):
        self.config = config
        self.context = context
        self.results: List[ScanResult] = []
        self.rate_limit = config.get('rate_limit', 10)
        self.timeout = config.get('timeout', 15)
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
        
    async def scan(self) -> List[ScanResult]:
        """Main scan method"""
        logger.info("Starting Workflow Bypass scan...")
        self.results = []
        
        base_url = self.config.get('target', {}).get('url', '')
        if not base_url:
            base_url = self.config.get('target_url', '')
        
        if not base_url:
            return self.results
        
        # Common multi-step workflow patterns
        workflows = [
            # Registration workflow
            ['/register/step1', '/register/step2', '/register/step3', '/register/complete'],
            # Checkout workflow
            ['/checkout/cart', '/checkout/address', '/checkout/payment', '/checkout/confirm'],
            # Verification workflow
            ['/verify/email', '/verify/phone', '/verify/complete'],
            # Password reset
            ['/reset/request', '/reset/verify', '/reset/newpassword'],
        ]
        
        connector = aiohttp.TCPConnector(ssl=self.ssl_context, limit=10)
        
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=self.timeout)
        ) as session:
            
            for workflow in workflows:
                await self._test_step_skipping(session, base_url, workflow)
        
        logger.info(f"Workflow bypass scan complete. Found {len(self.results)} vulnerabilities")
        return self.results
    
    async def _test_step_skipping(self, session: aiohttp.ClientSession, 
                                   base_url: str, workflow: List[str]):
        """Test if workflow steps can be skipped"""
        headers = {'User-Agent': 'Mozilla/5.0'}
        
        # Try to access final step directly without completing previous steps
        final_step = workflow[-1]
        url = urljoin(base_url, final_step)
        
        try:
            await asyncio.sleep(1 / self.rate_limit)
            
            async with session.get(url, headers=headers) as response:
                if response.status == 200:
                    body = await response.text()
                    
                    # Check if we got actual content (not a redirect to step 1)
                    if workflow[0] not in body and 'step1' not in body.lower():
                        result = ScanResult(
                            id=f"WORKFLOW-SKIP-{len(self.results)+1}",
                            category="A04:2021 - Insecure Design",
                            severity="high",
                            title="Workflow Step Skipping",
                            description=f"Final step {final_step} is accessible without completing previous steps.",
                            url=url,
                            method="GET",
                            evidence=f"Accessed {final_step} directly without workflow",
                            remediation="Enforce step completion server-side. Track workflow state in session.",
                            cwe_id="CWE-841",
                            poc=f"Navigate directly to {url}",
                            reasoning="Final workflow step accessible without prerequisites"
                        )
                        self.results.append(result)
                        
        except Exception as e:
            logger.debug(f"Step skipping test error: {e}")
