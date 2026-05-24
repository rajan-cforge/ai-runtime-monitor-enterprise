# API choice review rubric

Applied by `architect-reviewer` on every PR. The reviewer picks 3-5 highest-impact items — never enumerates the full list.

## Filesystem operations

PREFER `pathlib.Path`:
```python
Path("config.json").read_text()
Path("dir").iterdir()
Path(p).exists()
```

AVOID `os.path`:
```python
os.path.join(...)   # → Path(...) / "..."
os.path.exists(...) # → Path(...).exists()
os.listdir(...)     # → Path(...).iterdir() or .glob()
```

PREFER context managers:
```python
with Path(p).open() as f: ...
```

AVOID manual open/close:
```python
f = open(...); ...; f.close()
```

## HTTP

PREFER `httpx` in new code (project standard):
```python
with httpx.Client() as client:
    r = client.get(url)
```

AVOID `requests`:
```python
requests.get(url)  # legacy code only; new code uses httpx
```

## Structured data

PREFER `dataclasses` or `pydantic` for structured records:
```python
@dataclass(frozen=True)
class Finding: ...
```

AVOID dict-as-record:
```python
finding = {"type": "...", "severity": "..."}
```

PREFER `TypedDict` for dict-shaped data crossing API boundaries:
```python
class FindingDict(TypedDict): ...
```

## String formatting

PREFER f-strings:
```python
f"Found {n} issues"
```

AVOID:
```python
"Found {} issues".format(n)
"Found %d issues" % n
```

EXCEPTION: logging uses %-style for lazy formatting:
```python
logger.info("Found %d issues", n)
```

## Enumerations

PREFER `enum.StrEnum` or `enum.Enum`:
```python
class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
```

AVOID string constants:
```python
SEVERITY_CRITICAL = "critical"
```

## Date/time

PREFER timezone-aware datetimes:
```python
datetime.now(timezone.utc)
```

AVOID naive datetimes:
```python
datetime.now()  # ambiguous, locale-dependent
```

PREFER:
```python
datetime.fromisoformat(s)
```

AVOID:
```python
datetime.strptime(s, "...")  # slow, locale-dependent
```

## Collections

PREFER:
- `set(...)` for membership-test heavy code
- `collections.Counter` for counting
- `collections.defaultdict` where applicable
- list comprehension or generator expression where it fits

AVOID:
```python
for i in range(len(items)):  # → for item in items:
for x in items:
    if x:
        result.append(x)         # → [x for x in items if x]
```

## Identifiers

PREFER `uuid` or `hashlib`:
```python
uuid.uuid4().hex
```

AVOID:
```python
# ad-hoc string concatenation with timestamps
```

## Subprocess

PREFER argv list, never `shell=True`:
```python
subprocess.run(["cmd", "arg"], check=True)
```

AVOID:
```python
subprocess.run(f"cmd {arg}", shell=True)  # C4 fix established this
```

## Logging

PREFER:
```python
logger = logging.getLogger(__name__)
logger.exception("Failed to ...", extra={"context": x})
```

AVOID:
- `print()` in non-test code
- `logger.error("...", str(e))` — use `.exception()` for tracebacks
