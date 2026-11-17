#!/usr/bin/env python3
"""Build the tiny stdlib-only ``python -c`` authenticated bootstrap loader.

The generated text is the executable trust anchor.  A run must freeze that
exact text and its SHA-256 outside the project tree, invoke it with ``-I -S -B``
and a unique empty ``-X pycache_prefix=...``, and record the exact argv.  The
expected bootstrap digest is embedded as a literal; it is never accepted as
an invocation argument.
"""

from __future__ import annotations

import hashlib
import re


INLINE_LOADER_VERSION = "sluice-verified-inline-loader-v1"
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_PLACEHOLDER = "@BOOTSTRAP_SHA256@"

INLINE_LOADER_TEMPLATE = r'''import posix as os,sys
EXPECTED_BOOTSTRAP_SHA256="@BOOTSTRAP_SHA256@"
def dflags():
 f=os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC
 return f|(os.O_NOFOLLOW if hasattr(os,"O_NOFOLLOW") else 0)
def fflags():
 f=os.O_RDONLY|os.O_CLOEXEC
 return f|(os.O_NOFOLLOW if hasattr(os,"O_NOFOLLOW") else 0)
def did(s):
 if s.st_mode&0o170000!=0o040000: raise RuntimeError("bootstrap path component is not a directory")
 return [s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode&0o7777]
def fid(s):
 if s.st_mode&0o170000!=0o100000 or s.st_nlink!=1: raise RuntimeError("bootstrap is not a single-link regular file")
 return [s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def openchain(p):
 if not isinstance(p,str) or not p.startswith("/") or "\x00" in p: raise RuntimeError("bootstrap path is not absolute")
 parts=p.split("/")[1:]
 if not parts or any(not x or x in (".","..") for x in parts): raise RuntimeError("bootstrap path is not canonical")
 fd=os.open("/",dflags()); chain=[did(os.fstat(fd))]
 try:
  for x in parts[:-1]:
   child=os.open(x,dflags(),dir_fd=fd); chain.append(did(os.fstat(child))); os.close(fd); fd=child
  leaf=os.open(parts[-1],fflags(),dir_fd=fd)
 finally: os.close(fd)
 fid(os.fstat(leaf)); return leaf,chain
def opendirchain(p):
 if not isinstance(p,str) or not p.startswith("/") or "\x00" in p: raise RuntimeError("pycache path is not absolute")
 parts=p.split("/")[1:]
 if not parts or any(not x or x in (".","..") for x in parts): raise RuntimeError("pycache path is not canonical")
 fd=os.open("/",dflags()); chain=[did(os.fstat(fd))]
 try:
  for x in parts:
   child=os.open(x,dflags(),dir_fd=fd); chain.append(did(os.fstat(child))); os.close(fd); fd=child
  return fd,chain
 except BaseException:
  os.close(fd); raise
def readstable(fd):
 before=os.fstat(fd); identity=fid(before)
 if before.st_size>4194304: raise RuntimeError("bootstrap exceeds size limit")
 os.lseek(fd,0,0); chunks=[]; total=0
 while True:
  block=os.read(fd,min(1048576,4194305-total))
  if not block: break
  chunks.append(block); total+=len(block)
  if total>4194304: raise RuntimeError("bootstrap exceeds size limit")
 data=b"".join(chunks)
 if len(data)!=before.st_size or fid(os.fstat(fd))!=identity: raise RuntimeError("bootstrap changed during same-FD read")
 return data,identity
if sys.flags.isolated!=1 or sys.flags.no_site!=1 or sys.dont_write_bytecode is not True: raise RuntimeError("verified inline interpreter flags are incomplete")
prefix=sys.pycache_prefix
prefix_fd,prefix_binding=opendirchain(prefix)
prefix_status=os.fstat(prefix_fd)
prefix_identity=did(prefix_status)
if prefix_status.st_uid!=os.geteuid() or prefix_status.st_mode&0o7777!=0o700 or os.listdir(prefix_fd): raise RuntimeError("verified inline pycache prefix is not fresh/private/empty")
import hashlib
if len(sys.argv)<7: raise RuntimeError("verified inline loader argv schema is invalid")
bootstrap_path,manifest_path,manifest_sha256,inline_sha256,run_id,source_commit=sys.argv[1:7]
entry_argv=sys.argv[7:]
bootstrap_fd,binding=openchain(bootstrap_path)
try:
 payload,identity=readstable(bootstrap_fd)
 if hashlib.sha256(payload).hexdigest()!=EXPECTED_BOOTSTRAP_SHA256: raise RuntimeError("bootstrap digest mismatch")
 context={"bootstrap_binding":binding,"bootstrap_fd":bootstrap_fd,"bootstrap_path":bootstrap_path,"bootstrap_sha256":EXPECTED_BOOTSTRAP_SHA256,"closure_manifest_path":manifest_path,"closure_manifest_sha256":manifest_sha256,"inline_loader_sha256":inline_sha256,"pycache_binding":prefix_binding,"pycache_fd":prefix_fd,"pycache_identity":prefix_identity,"run_id":run_id,"source_commit":source_commit}
 namespace={"__builtins__":__builtins__,"__file__":bootstrap_path,"__name__":"__verified_execution_bootstrap__","VERIFIED_ENTRY_ARGV":entry_argv,"VERIFIED_INLINE_LOADER":context}
 exec(compile(payload,bootstrap_path,"exec",dont_inherit=True),namespace)
 result=namespace["main"]()
 if type(result) is not int: raise RuntimeError("bootstrap returned non-integer")
finally: os.close(bootstrap_fd); os.close(prefix_fd)
raise SystemExit(result)
'''


def build_inline_loader_source(expected_bootstrap_sha256: str) -> str:
    """Return exact executable loader text with one embedded bootstrap digest."""

    if (
        type(expected_bootstrap_sha256) is not str
        or _SHA256.fullmatch(expected_bootstrap_sha256) is None
    ):
        raise ValueError("expected_bootstrap_sha256 must be lowercase SHA-256")
    if INLINE_LOADER_TEMPLATE.count(_PLACEHOLDER) != 1:
        raise RuntimeError("inline loader template placeholder is not unique")
    return INLINE_LOADER_TEMPLATE.replace(_PLACEHOLDER, expected_bootstrap_sha256)


def inline_loader_sha256(source: str) -> str:
    if type(source) is not str or not source.endswith("\n"):
        raise ValueError("inline loader source must be newline-terminated text")
    return hashlib.sha256(source.encode("ascii")).hexdigest()
