"""
FLUX Packager — bundle bytecode programs into self-contained packages.

A .fluxpack is a JSON envelope containing:
- Metadata (name, version, author, description)
- Bytecode (compiled program)
- Dependencies (other packages needed)
- Test vectors (input/output pairs for validation)
- Manifest (checksums, sizes)
"""
import json
import hashlib
import time
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Tuple
from enum import Enum


class PackFormat(Enum):
    RAW = "raw"           # Just bytecode
    PACKED = "packed"     # With metadata
    SIGNED = "signed"     # With checksum verification


@dataclass
class TestVector:
    name: str
    inputs: Dict[int, int]
    expected: Dict[int, int]
    max_cycles: int = 10000


@dataclass
class FluxPackage:
    name: str
    version: str
    author: str
    description: str
    bytecode: List[int]
    entry_point: int = 0
    inputs: List[str] = field(default_factory=list)
    outputs: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    test_vectors: List[TestVector] = field(default_factory=list)
    created_at: str = ""
    checksum: str = ""
    bytecode_size: int = 0
    
    def __post_init__(self):
        if not self.created_at:
            self.created_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        if not self.bytecode_size:
            self.bytecode_size = len(self.bytecode)
        if not self.checksum:
            self.checksum = hashlib.sha256(bytes(self.bytecode)).hexdigest()[:16]
    
    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)
    
    def to_binary(self) -> bytes:
        """Compact binary format: header + bytecode."""
        header = {
            "n": self.name, "v": self.version, "a": self.author,
            "sz": self.bytecode_size, "ck": self.checksum,
            "in": self.inputs, "out": self.outputs,
        }
        header_bytes = json.dumps(header, separators=(',', ':')).encode()
        # Format: [2B header_len][header][bytecode]
        header_len = len(header_bytes)
        return header_len.to_bytes(2, 'big') + header_bytes + bytes(self.bytecode)
    
    @classmethod
    def from_json(cls, data: str) -> 'FluxPackage':
        d = json.loads(data)
        if 'test_vectors' in d:
            d['test_vectors'] = [TestVector(**tv) if isinstance(tv, dict) else tv for tv in d['test_vectors']]
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})
    
    @classmethod
    def from_binary(cls, data: bytes) -> 'FluxPackage':
        header_len = int.from_bytes(data[:2], 'big')
        header = json.loads(data[2:2+header_len])
        bytecode = list(data[2+header_len:])
        return cls(
            name=header['n'], version=header.get('v','1.0.0'),
            author=header.get('a',''), description='',
            bytecode=bytecode, inputs=header.get('in',[]),
            outputs=header.get('out',[])
        )
    
    def verify(self) -> bool:
        actual = hashlib.sha256(bytes(self.bytecode)).hexdigest()[:16]
        return actual == self.checksum
    
    def run_tests(self) -> List[Tuple[str, bool, str]]:
        """Run all test vectors. Returns (name, passed, detail)."""
        results = []
        for tv in self.test_vectors:
            regs, cycles = self._execute(tv.inputs)
            passed = all(regs.get(k, 0) == v for k, v in tv.expected.items())
            detail = "PASS" if passed else f"FAIL: got {dict(regs)}, expected {tv.expected}"
            results.append((tv.name, passed, detail))
        return results
    
    def _execute(self, initial: Dict[int, int]) -> Tuple[Dict[int, int], int]:
        regs = [0] * 64
        stack = [0] * 4096
        sp = 4096
        pc = 0
        cycles = 0
        
        for k, v in initial.items():
            regs[k] = v
        
        def sb(b): return b - 256 if b > 127 else b
        bc = bytes(self.bytecode)
        
        while pc < len(bc) and cycles < 100000:
            op = bc[pc]; cycles += 1
            if op == 0x00: break
            elif op == 0x08: regs[bc[pc+1]] += 1; pc += 2
            elif op == 0x09: regs[bc[pc+1]] -= 1; pc += 2
            elif op == 0x0C: sp -= 1; stack[sp] = regs[bc[pc+1]]; pc += 2
            elif op == 0x0D: regs[bc[pc+1]] = stack[sp]; sp += 1; pc += 2
            elif op == 0x18: regs[bc[pc+1]] = sb(bc[pc+2]); pc += 3
            elif op == 0x20: regs[bc[pc+1]] = regs[bc[pc+2]] + regs[bc[pc+3]]; pc += 4
            elif op == 0x21: regs[bc[pc+1]] = regs[bc[pc+2]] - regs[bc[pc+3]]; pc += 4
            elif op == 0x22: regs[bc[pc+1]] = regs[bc[pc+2]] * regs[bc[pc+3]]; pc += 4
            elif op == 0x23:
                if regs[bc[pc+3]] != 0: regs[bc[pc+1]] = regs[bc[pc+2]] // regs[bc[pc+3]]
                pc += 4
            elif op == 0x24:
                if regs[bc[pc+3]] != 0: regs[bc[pc+1]] = regs[bc[pc+2]] % regs[bc[pc+3]]
                pc += 4
            elif op == 0x2C: regs[bc[pc+1]] = 1 if regs[bc[pc+2]] == regs[bc[pc+3]] else 0; pc += 4
            elif op == 0x2D: regs[bc[pc+1]] = 1 if regs[bc[pc+2]] < regs[bc[pc+3]] else 0; pc += 4
            elif op == 0x2E: regs[bc[pc+1]] = 1 if regs[bc[pc+2]] > regs[bc[pc+3]] else 0; pc += 4
            elif op == 0x3A: regs[bc[pc+1]] = regs[bc[pc+2]]; pc += 4
            elif op == 0x3C:
                if regs[bc[pc+1]] == 0: pc += sb(bc[pc+2])
                else: pc += 4
            elif op == 0x3D:
                if regs[bc[pc+1]] != 0: pc += sb(bc[pc+2])
                else: pc += 4
            else: pc += 1
        
        return {i: regs[i] for i in range(16)}, cycles


class PackRegistry:
    """Simple local package registry."""
    def __init__(self):
        self.packages: Dict[str, FluxPackage] = {}
    
    def add(self, pkg: FluxPackage):
        self.packages[pkg.name] = pkg
    
    def get(self, name: str) -> Optional[FluxPackage]:
        return self.packages.get(name)
    
    def list(self) -> List[str]:
        return sorted(self.packages.keys())
    
    def search(self, query: str) -> List[FluxPackage]:
        q = query.lower()
        return [p for p in self.packages.values() 
                if q in p.name.lower() or q in p.description.lower()]
    
    def verify_all(self) -> Dict[str, bool]:
        return {name: pkg.verify() for name, pkg in self.packages.items()}


# ── Tests ──────────────────────────────────────────────

import unittest


class TestPackager(unittest.TestCase):
    def _make_pkg(self, name="test", bc=None):
        return FluxPackage(
            name=name, version="1.0.0", author="oracle1",
            description="test package", bytecode=bc or [0x18, 0, 42, 0x00],
            inputs=["R0"], outputs=["R0"]
        )
    
    def test_create_package(self):
        pkg = self._make_pkg()
        self.assertEqual(pkg.bytecode_size, 4)
        self.assertTrue(pkg.checksum)
    
    def test_json_roundtrip(self):
        pkg = self._make_pkg()
        json_str = pkg.to_json()
        pkg2 = FluxPackage.from_json(json_str)
        self.assertEqual(pkg.bytecode, pkg2.bytecode)
        self.assertEqual(pkg.name, pkg2.name)
    
    def test_binary_roundtrip(self):
        pkg = self._make_pkg()
        binary = pkg.to_binary()
        pkg2 = FluxPackage.from_binary(binary)
        self.assertEqual(pkg.bytecode, pkg2.bytecode)
    
    def test_verify_checksum(self):
        pkg = self._make_pkg()
        self.assertTrue(pkg.verify())
    
    def test_verify_tampered(self):
        pkg = self._make_pkg()
        pkg.bytecode[0] = 0xFF
        self.assertFalse(pkg.verify())
    
    def test_test_vectors(self):
        pkg = FluxPackage(
            name="add", version="1.0.0", author="test",
            description="add two numbers",
            bytecode=[0x18,0,10, 0x18,1,20, 0x20,2,0,1, 0x00],
            inputs=["R0","R1"], outputs=["R2"],
            test_vectors=[
                TestVector("basic", {}, {2:30}),
                TestVector("same", {}, {2:30}),
            ]
        )
        results = pkg.run_tests()
        self.assertTrue(all(p for _, p, _ in results))
        self.assertEqual(len(results), 2)
    
    def test_registry(self):
        reg = PackRegistry()
        reg.add(self._make_pkg("pkg_a"))
        reg.add(self._make_pkg("pkg_b"))
        self.assertEqual(len(reg.list()), 2)
        self.assertIsNotNone(reg.get("pkg_a"))
    
    def test_registry_search(self):
        reg = PackRegistry()
        reg.add(FluxPackage("sort", "1.0", "test", "sort algorithm", [0x00]))
        reg.add(FluxPackage("math", "1.0", "test", "math operations", [0x00]))
        results = reg.search("sort")
        self.assertEqual(len(results), 1)
    
    def test_registry_verify(self):
        reg = PackRegistry()
        reg.add(self._make_pkg("good"))
        results = reg.verify_all()
        self.assertTrue(all(results.values()))


if __name__ == "__main__":
    unittest.main(verbosity=2)
