"""
Jarwis AI Training - Knowledge Extractor

Extracts structured security knowledge from crawled web content.
Parses different site formats (OWASP, CWE, PortSwigger, etc.) and
outputs standardized knowledge entries for the Jarwis AI.

No LLM or external API required - uses pattern matching and HTML parsing.
"""

import hashlib
import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from bs4 import BeautifulSoup

from .web_crawler import CrawlResult, CrawlSession

logger = logging.getLogger(__name__)


@dataclass
class ExtractedKnowledge:
    """A piece of extracted security knowledge"""
    knowledge_id: str
    knowledge_type: str  # vulnerability, remediation, concept, pattern
    
    # Core content
    name: str
    description: str
    
    # Classification
    owasp_category: Optional[str] = None
    cwe_id: Optional[str] = None
    severity: Optional[str] = None
    
    # Details
    impact: List[str] = field(default_factory=list)
    examples: List[str] = field(default_factory=list)
    remediation: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    
    # Extracted patterns (for pattern matcher)
    detection_patterns: List[str] = field(default_factory=list)
    
    # Metadata
    source_url: str = ""
    source_type: str = ""
    extracted_at: str = field(default_factory=lambda: datetime.now().isoformat())
    confidence: float = 0.8  # Confidence in extraction accuracy
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "knowledge_id": self.knowledge_id,
            "knowledge_type": self.knowledge_type,
            "name": self.name,
            "description": self.description,
            "owasp_category": self.owasp_category,
            "cwe_id": self.cwe_id,
            "severity": self.severity,
            "impact": self.impact,
            "examples": self.examples,
            "remediation": self.remediation,
            "references": self.references,
            "detection_patterns": self.detection_patterns,
            "source_url": self.source_url,
            "source_type": self.source_type,
            "extracted_at": self.extracted_at,
            "confidence": self.confidence
        }


class KnowledgeExtractor:
    """
    Extracts structured knowledge from crawled security content.
    
    Supports different site types with specialized parsers:
    - OWASP: Top 10, Cheat Sheets, Testing Guide
    - CWE: Common Weakness Enumeration
    - PortSwigger: Web Security Academy
    - Custom: Generic extraction
    """
    
    # Vulnerability name patterns
    VULN_PATTERNS = [
        r"(SQL\s*Injection|SQLi)",
        r"(Cross[- ]Site\s*Scripting|XSS)",
        r"(Cross[- ]Site\s*Request\s*Forgery|CSRF)",
        r"(Server[- ]Side\s*Request\s*Forgery|SSRF)",
        r"(XML\s*External\s*Entity|XXE)",
        r"(Insecure\s*Direct\s*Object\s*Reference|IDOR)",
        r"(Remote\s*Code\s*Execution|RCE)",
        r"(Local\s*File\s*Inclusion|LFI)",
        r"(Remote\s*File\s*Inclusion|RFI)",
        r"(Path\s*Traversal|Directory\s*Traversal)",
        r"(Command\s*Injection|OS\s*Command\s*Injection)",
        r"(LDAP\s*Injection)",
        r"(NoSQL\s*Injection)",
        r"(Template\s*Injection|SSTI)",
        r"(Broken\s*Access\s*Control)",
        r"(Broken\s*Authentication)",
        r"(Sensitive\s*Data\s*Exposure)",
        r"(Security\s*Misconfiguration)",
        r"(Insecure\s*Deserialization)",
        r"(Using\s*Components\s*with\s*Known\s*Vulnerabilities)",
        r"(Insufficient\s*Logging)",
        r"(Clickjacking)",
        r"(Open\s*Redirect)",
        r"(HTTP\s*Request\s*Smuggling)",
        r"(Race\s*Condition)",
        r"(Prototype\s*Pollution)",
        r"(JWT\s*vulnerabilit)",
        r"(OAuth\s*vulnerabilit)",
        r"(WebSocket\s*vulnerabilit)",
        r"(GraphQL\s*vulnerabilit)",
        r"(API\s*Security)",
        r"(Authentication\s*Bypass)",
        r"(Privilege\s*Escalation)",
        r"(Session\s*Hijacking)",
        r"(Session\s*Fixation)",
        r"(Buffer\s*Overflow)",
        r"(Denial\s*of\s*Service|DoS)",
        r"(XML\s*Injection)",
        r"(XPath\s*Injection)",
        r"(Header\s*Injection)",
        r"(CRLF\s*Injection)",
        r"(Log\s*Injection)",
        r"(Email\s*Injection)",
    ]
    
    # OWASP category patterns
    OWASP_PATTERNS = {
        "A01": r"A01[:\s\-]+Broken\s*Access\s*Control",
        "A02": r"A02[:\s\-]+Cryptographic\s*Failures",
        "A03": r"A03[:\s\-]+Injection",
        "A04": r"A04[:\s\-]+Insecure\s*Design",
        "A05": r"A05[:\s\-]+Security\s*Misconfiguration",
        "A06": r"A06[:\s\-]+Vulnerable.*Components",
        "A07": r"A07[:\s\-]+Identification.*Authentication",
        "A08": r"A08[:\s\-]+Software.*Data\s*Integrity",
        "A09": r"A09[:\s\-]+Security\s*Logging.*Monitoring",
        "A10": r"A10[:\s\-]+Server[- ]Side\s*Request\s*Forgery",
    }
    
    # Severity indicators
    SEVERITY_PATTERNS = {
        "critical": r"\b(critical|catastrophic|severe|emergency)\b",
        "high": r"\b(high|serious|major|significant)\b",
        "medium": r"\b(medium|moderate|normal)\b",
        "low": r"\b(low|minor|informational|info)\b",
    }
    
    # Remediation section indicators
    REMEDIATION_INDICATORS = [
        r"(how\s+to\s+(fix|prevent|remediate|mitigate))",
        r"(remediation|mitigation|prevention|countermeasure)",
        r"(recommendation|best\s+practice|solution)",
        r"(defense|protection|safeguard)",
    ]
    
    def __init__(self):
        self.extracted: List[ExtractedKnowledge] = []
        self._vuln_patterns = [re.compile(p, re.IGNORECASE) for p in self.VULN_PATTERNS]
        self._owasp_patterns = {k: re.compile(v, re.IGNORECASE) for k, v in self.OWASP_PATTERNS.items()}
        self._severity_patterns = {k: re.compile(v, re.IGNORECASE) for k, v in self.SEVERITY_PATTERNS.items()}
        self._remediation_pattern = re.compile("|".join(self.REMEDIATION_INDICATORS), re.IGNORECASE)
    
    def extract_from_session(self, session: CrawlSession) -> List[ExtractedKnowledge]:
        """Extract knowledge from all pages in a crawl session"""
        logger.info(f"Extracting knowledge from {session.site_name} ({session.pages_crawled} pages)")
        
        results = []
        for page in session.results:
            if page.success:
                extracted = self.extract_from_page(page, session.site_type)
                results.extend(extracted)
        
        logger.info(f"Extracted {len(results)} knowledge entries from {session.site_name}")
        self.extracted.extend(results)
        return results
    
    def extract_from_page(
        self,
        page: CrawlResult,
        site_type: str = "custom"
    ) -> List[ExtractedKnowledge]:
        """Extract knowledge from a single page"""
        # Route to specialized extractor based on site type
        extractors = {
            "owasp": self._extract_owasp,
            "cwe": self._extract_cwe,
            "portswigger": self._extract_portswigger,
            "hackerone": self._extract_hackerone,
            "custom": self._extract_generic,
        }
        
        extractor = extractors.get(site_type, self._extract_generic)
        return extractor(page)
    
    def _extract_owasp(self, page: CrawlResult) -> List[ExtractedKnowledge]:
        """Extract from OWASP pages"""
        results = []
        soup = BeautifulSoup(page.html, "html.parser")
        
        # Find main content
        main_content = soup.find("main") or soup.find("article") or soup.find("div", class_="content")
        if not main_content:
            main_content = soup.body
        
        if not main_content:
            return results
        
        text = main_content.get_text(separator="\n", strip=True)
        
        # Detect OWASP category
        owasp_cat = None
        for cat, pattern in self._owasp_patterns.items():
            if pattern.search(text):
                owasp_cat = cat
                break
        
        # Detect vulnerability type
        vuln_name = self._detect_vulnerability_name(page.title, text)
        
        if vuln_name:
            # Extract sections
            description = self._extract_description(main_content)
            impact = self._extract_impact(main_content)
            remediation = self._extract_remediation(main_content)
            examples = self._extract_code_examples(main_content)
            severity = self._detect_severity(text)
            
            knowledge = ExtractedKnowledge(
                knowledge_id=self._generate_id(page.url, vuln_name),
                knowledge_type="vulnerability",
                name=vuln_name,
                description=description,
                owasp_category=owasp_cat,
                severity=severity,
                impact=impact,
                examples=examples,
                remediation=remediation,
                references=[page.url],
                source_url=page.url,
                source_type="owasp",
                confidence=0.9
            )
            results.append(knowledge)
        
        return results
    
    def _extract_cwe(self, page: CrawlResult) -> List[ExtractedKnowledge]:
        """Extract from CWE pages"""
        results = []
        soup = BeautifulSoup(page.html, "html.parser")
        
        # CWE pages have structured content
        # Find CWE ID from URL or content
        cwe_match = re.search(r"CWE-(\d+)", page.url + page.title, re.IGNORECASE)
        cwe_id = f"CWE-{cwe_match.group(1)}" if cwe_match else None
        
        # Find main content
        main = soup.find("div", id="Content") or soup.find("main") or soup.body
        if not main:
            return results
        
        text = main.get_text(separator="\n", strip=True)
        
        # Get name from title or heading
        name = page.title
        h1 = soup.find("h1")
        if h1:
            name = h1.get_text(strip=True)
        
        if cwe_id or self._detect_vulnerability_name(name, text):
            description = self._extract_description(main)
            impact = self._extract_section(main, ["Consequences", "Impact", "Technical Impact"])
            remediation = self._extract_section(main, ["Potential Mitigations", "Mitigation", "Remediation"])
            
            knowledge = ExtractedKnowledge(
                knowledge_id=self._generate_id(page.url, cwe_id or name),
                knowledge_type="vulnerability",
                name=name,
                description=description,
                cwe_id=cwe_id,
                severity=self._detect_severity(text),
                impact=impact,
                remediation=remediation,
                references=[page.url],
                source_url=page.url,
                source_type="cwe",
                confidence=0.85
            )
            results.append(knowledge)
        
        return results
    
    def _extract_portswigger(self, page: CrawlResult) -> List[ExtractedKnowledge]:
        """Extract from PortSwigger Web Security Academy"""
        results = []
        soup = BeautifulSoup(page.html, "html.parser")
        
        # PortSwigger has good structure
        article = soup.find("article") or soup.find("div", class_="content") or soup.body
        if not article:
            return results
        
        text = article.get_text(separator="\n", strip=True)
        vuln_name = self._detect_vulnerability_name(page.title, text)
        
        if vuln_name:
            description = self._extract_description(article)
            examples = self._extract_code_examples(article)
            remediation = self._extract_remediation(article)
            
            # PortSwigger often has "How to prevent" sections
            prevent_section = article.find(
                lambda tag: tag.name in ["h2", "h3"] and 
                "prevent" in tag.get_text().lower()
            )
            if prevent_section:
                prevention = self._extract_following_content(prevent_section)
                remediation.extend(prevention)
            
            knowledge = ExtractedKnowledge(
                knowledge_id=self._generate_id(page.url, vuln_name),
                knowledge_type="vulnerability",
                name=vuln_name,
                description=description,
                severity=self._detect_severity(text),
                examples=examples,
                remediation=remediation,
                references=[page.url],
                source_url=page.url,
                source_type="portswigger",
                confidence=0.9
            )
            results.append(knowledge)
        
        return results
    
    def _extract_hackerone(self, page: CrawlResult) -> List[ExtractedKnowledge]:
        """Extract from HackerOne pages"""
        # Similar to generic but tailored for HackerOne structure
        return self._extract_generic(page, source_type="hackerone")
    
    def _extract_generic(
        self,
        page: CrawlResult,
        source_type: str = "custom"
    ) -> List[ExtractedKnowledge]:
        """Generic extractor for any security content"""
        results = []
        soup = BeautifulSoup(page.html, "html.parser")
        
        # Find main content
        main = soup.find("main") or soup.find("article") or soup.find("div", class_="content") or soup.body
        if not main:
            return results
        
        text = main.get_text(separator="\n", strip=True)
        
        # Check if this page is about a vulnerability
        vuln_name = self._detect_vulnerability_name(page.title, text)
        
        if vuln_name:
            description = self._extract_description(main)
            
            # Only create entry if we have meaningful content
            if len(description) > 100:
                knowledge = ExtractedKnowledge(
                    knowledge_id=self._generate_id(page.url, vuln_name),
                    knowledge_type="vulnerability",
                    name=vuln_name,
                    description=description,
                    severity=self._detect_severity(text),
                    impact=self._extract_impact(main),
                    examples=self._extract_code_examples(main),
                    remediation=self._extract_remediation(main),
                    references=[page.url],
                    source_url=page.url,
                    source_type=source_type,
                    confidence=0.7
                )
                results.append(knowledge)
        
        return results
    
    # ===== HELPER METHODS =====
    
    def _detect_vulnerability_name(self, title: str, text: str) -> Optional[str]:
        """Detect if content is about a specific vulnerability"""
        combined = f"{title}\n{text[:2000]}"
        
        for pattern in self._vuln_patterns:
            match = pattern.search(combined)
            if match:
                return match.group(0)
        
        return None
    
    def _detect_severity(self, text: str) -> str:
        """Detect severity from text"""
        text_lower = text.lower()
        for severity, pattern in self._severity_patterns.items():
            if pattern.search(text_lower):
                return severity
        return "medium"  # Default
    
    def _extract_description(self, soup) -> str:
        """Extract main description from content"""
        # Try to find first few paragraphs
        paragraphs = soup.find_all("p", limit=5)
        description = []
        
        for p in paragraphs:
            text = p.get_text(strip=True)
            if len(text) > 50:  # Skip short paragraphs
                description.append(text)
        
        return "\n\n".join(description[:3])
    
    def _extract_impact(self, soup) -> List[str]:
        """Extract impact statements"""
        impacts = []
        
        # Look for impact section
        impact_section = soup.find(
            lambda tag: tag.name in ["h2", "h3", "h4"] and 
            any(word in tag.get_text().lower() for word in ["impact", "consequence", "risk"])
        )
        
        if impact_section:
            # Get following list items or paragraphs
            next_elem = impact_section.find_next_sibling()
            while next_elem and next_elem.name not in ["h2", "h3", "h4"]:
                if next_elem.name == "ul":
                    for li in next_elem.find_all("li"):
                        impacts.append(li.get_text(strip=True))
                elif next_elem.name == "p":
                    text = next_elem.get_text(strip=True)
                    if len(text) > 20:
                        impacts.append(text)
                next_elem = next_elem.find_next_sibling()
        
        return impacts[:10]  # Limit to 10 impacts
    
    def _extract_remediation(self, soup) -> List[str]:
        """Extract remediation steps"""
        remediations = []
        
        # Look for remediation section
        remediation_section = soup.find(
            lambda tag: tag.name in ["h2", "h3", "h4"] and 
            self._remediation_pattern.search(tag.get_text())
        )
        
        if remediation_section:
            next_elem = remediation_section.find_next_sibling()
            while next_elem and next_elem.name not in ["h2", "h3", "h4"]:
                if next_elem.name == "ul" or next_elem.name == "ol":
                    for li in next_elem.find_all("li"):
                        remediations.append(li.get_text(strip=True))
                elif next_elem.name == "p":
                    text = next_elem.get_text(strip=True)
                    if len(text) > 20:
                        remediations.append(text)
                next_elem = next_elem.find_next_sibling()
        
        return remediations[:10]
    
    def _extract_code_examples(self, soup) -> List[str]:
        """Extract code examples"""
        examples = []
        
        # Find code blocks
        for code_block in soup.find_all(["pre", "code"]):
            code = code_block.get_text(strip=True)
            if len(code) > 20 and len(code) < 2000:
                examples.append(code)
        
        return examples[:5]  # Limit to 5 examples
    
    def _extract_section(self, soup, section_names: List[str]) -> List[str]:
        """Extract content from a named section"""
        content = []
        
        for name in section_names:
            section = soup.find(
                lambda tag: tag.name in ["h2", "h3", "h4"] and 
                name.lower() in tag.get_text().lower()
            )
            if section:
                content.extend(self._extract_following_content(section))
                break
        
        return content
    
    def _extract_following_content(self, heading) -> List[str]:
        """Extract content following a heading"""
        content = []
        next_elem = heading.find_next_sibling()
        
        while next_elem and next_elem.name not in ["h2", "h3", "h4"]:
            if next_elem.name == "ul" or next_elem.name == "ol":
                for li in next_elem.find_all("li"):
                    content.append(li.get_text(strip=True))
            elif next_elem.name == "p":
                text = next_elem.get_text(strip=True)
                if len(text) > 20:
                    content.append(text)
            next_elem = next_elem.find_next_sibling()
        
        return content[:10]
    
    def _generate_id(self, url: str, name: str) -> str:
        """Generate unique ID for knowledge entry"""
        combined = f"{url}:{name}"
        return hashlib.md5(combined.encode()).hexdigest()[:12]
    
    def save_extracted(self, output_path: Path):
        """Save all extracted knowledge to JSON"""
        data = {
            "extracted_at": datetime.now().isoformat(),
            "total_entries": len(self.extracted),
            "knowledge": [k.to_dict() for k in self.extracted]
        }
        
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Saved {len(self.extracted)} knowledge entries to {output_path}")
    
    def load_extracted(self, input_path: Path) -> List[ExtractedKnowledge]:
        """Load previously extracted knowledge"""
        with open(input_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        
        entries = []
        for k in data.get("knowledge", []):
            entry = ExtractedKnowledge(
                knowledge_id=k["knowledge_id"],
                knowledge_type=k["knowledge_type"],
                name=k["name"],
                description=k["description"],
                owasp_category=k.get("owasp_category"),
                cwe_id=k.get("cwe_id"),
                severity=k.get("severity"),
                impact=k.get("impact", []),
                examples=k.get("examples", []),
                remediation=k.get("remediation", []),
                references=k.get("references", []),
                detection_patterns=k.get("detection_patterns", []),
                source_url=k.get("source_url", ""),
                source_type=k.get("source_type", ""),
                extracted_at=k.get("extracted_at", ""),
                confidence=k.get("confidence", 0.7)
            )
            entries.append(entry)
        
        logger.info(f"Loaded {len(entries)} knowledge entries from {input_path}")
        return entries
