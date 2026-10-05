"""Local tools and explicit operator registrations; never discover workspace code."""
from __future__ import annotations

import hashlib
import csv
import inspect
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
import types
from decimal import Decimal, localcontext
from typing import Any, Literal

from jsonschema import Draft202012Validator, SchemaError
from pydantic import BaseModel, ConfigDict, Field, StrictStr, model_validator

DEFAULT_TOOLS = ('read_file', 'write_file', 'edit_file', 'list_files', 'grep', 'shell', 'calculate', 'read_csv')
BOUNDARIES = {name: 'shell' if name == 'shell' else 'write' if name in ('write_file', 'edit_file')
              else 'read' for name in DEFAULT_TOOLS}
SCHEMA_KEYS = frozenset({'type', 'properties', 'required', 'additionalProperties', 'items', 'enum',
    'minLength', 'maxLength', 'minItems', 'maxItems', 'minProperties', 'maxProperties',
    'minimum', 'maximum', 'exclusiveMinimum', 'exclusiveMaximum', 'title', 'description', 'default'})


class ToolContractError(ValueError):
    """Fixed local tool-contract failure, without private paths or exception text."""


def csv_document(data: bytes, max_text_bytes: int) -> str:
    """Preserve UTF8 CSV string cells and exact original physical row text locally."""
    try:
        text = data.decode('utf-8')
        physical = io.StringIO(text, newline='').readlines()
        reader_text = text.removeprefix('\ufeff')
        if text and not reader_text:
            reader_text = '\n'  # Preserve a marker-only source as an empty row.
        reader = csv.reader(io.StringIO(reader_text, newline=''), strict=True)
        output, used, start = [], 0, 0
        for index, cells in enumerate(reader):
            line = json.dumps({'row':index, 'cells':cells, 'source_start_line':start+1,
                'source_end_line':reader.line_num,
                'source_text':''.join(physical[start:reader.line_num])}, ensure_ascii=True)
            used += len(line.encode('utf-8')) + 1
            if len(line) > 59000 or used > max_text_bytes:
                raise ToolContractError('csv_output_limit')
            output.append(line)
            start = reader.line_num
        return '\n'.join(output)
    except (UnicodeError, csv.Error):
        raise ToolContractError('csv_invalid_document') from None


def csv_tool(read_bytes, page_text, max_text_bytes: int):
    """Build the CSV tool using the worker's existing bounded filesystem reader."""
    from pydantic_ai import Tool
    from pydantic_ai.exceptions import ToolFailed

    def read_csv(path: StrictStr, offset: int = 0, limit: int | None = None) -> str:
        """Read comma-delimited UTF8 CSV as raw string rows with source provenance.

        Args:
            path: Local .csv file within the workspace or granted private scratch.
            offset: Zero-based logical row to start reading, never a byte offset.
            limit: Optional positive row count, bounded by the local read window.

        Returns:
            Paged JSON rows with cells, exact source_text and physical line ranges.
            No numeric conversion, header inference or formula evaluation occurs.
            Invalid CSV, unsafe files and size/window errors produce a fixed local
            failure; this read does not authorize disclosure or additional tools.
        """
        try:
            if Path(path).suffix.lower() != '.csv':
                raise ToolContractError('csv_invalid_document')
            return page_text(csv_document(read_bytes(path), max_text_bytes), offset, limit)
        except Exception:
            raise ToolFailed('The local CSV cannot be read with these settings.') from None

    return Tool(read_csv, takes_ctx=False, sequential=True)


class ExtensionSpec(BaseModel):
    model_config = ConfigDict(extra='forbid', frozen=True)
    name: StrictStr = Field(pattern=r'^[a-z][a-z0-9_]{0,63}$')
    boundary: Literal['read', 'write', 'shell']
    module: Path
    sha256: StrictStr = Field(pattern=r'^[0-9a-f]{64}$')
    handler: StrictStr = Field(pattern=r'^[A-Za-z][A-Za-z0-9_]{0,63}$')
    description: StrictStr = Field(min_length=1, max_length=4000)
    parameters: dict[str, Any]

    @model_validator(mode='after')
    def contract(self):
        if self.name in BOUNDARIES or not self.module.is_absolute():
            raise ValueError('invalid extension registration')
        if len(json.dumps(self.parameters, allow_nan=False).encode()) > 32768:
            raise ValueError('extension schema too large')
        pending = [(self.parameters, 0)]
        visited = 0
        while pending:
            item, depth = pending.pop()
            visited += 1
            if depth > 16 or visited > 256 or not isinstance(item, dict) or set(item)-SCHEMA_KEYS:
                raise ValueError('unsupported extension schema')
            if (not isinstance(item.get('properties', {}), dict) or
                    ('additionalProperties' in item and type(item['additionalProperties']) is not bool)):
                raise ValueError('unsupported extension schema')
            literals = [(item['enum'], depth+1)] if 'enum' in item else []
            while literals:
                value, level = literals.pop()
                visited += 1
                if level > 16 or visited > 256:
                    raise ValueError('unsupported extension schema')
                if isinstance(value, dict):literals.extend((part,level+1) for part in value.values())
                elif isinstance(value, list):literals.extend((part,level+1) for part in value)
            pending.extend((value, depth+1) for value in item.get('properties', {}).values())
            if 'items' in item:pending.append((item['items'], depth+1))
        if self.parameters.get('type') != 'object' or self.parameters.get('additionalProperties') is not False:
            raise ValueError('extension requires a closed object schema')
        try:
            Draft202012Validator.check_schema(self.parameters)
        except SchemaError:
            raise ValueError('invalid extension schema') from None
        return self


def boundaries(extensions=()) -> dict[str, str]:
    result = dict(BOUNDARIES)
    for extension in extensions:
        if extension.name in result:
            raise ToolContractError('extension_duplicate_name')
        result[extension.name] = extension.boundary
    return result


def validate_arguments(extension: ExtensionSpec, arguments: dict) -> None:
    pending, visited = [(arguments, 0)], 0
    while pending:
        value, depth = pending.pop()
        visited += 1
        if depth > 32 or visited > 65536:
            raise ToolContractError('extension_invalid_arguments')
        if isinstance(value, dict):pending.extend((item,depth+1) for item in value.values())
        elif isinstance(value, list):pending.extend((item,depth+1) for item in value)
    if not isinstance(arguments, dict) or not Draft202012Validator(extension.parameters).is_valid(arguments):
        raise ToolContractError('extension_invalid_arguments')


def module_bytes(extension: ExtensionSpec, *, forbidden=()) -> bytes:
    """Read pinned bytes once from an owned regular file outside forbidden trees."""
    path = extension.module
    try:
        resolved = path.resolve(strict=True)
        if resolved != path or any(resolved == root or root in resolved.parents or resolved in root.parents
                                  for root in forbidden):
            raise ToolContractError('extension_unsafe_module')
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, 'rb') as stream:
            before = os.fstat(stream.fileno())
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or before.st_nlink != 1
                    or before.st_mode & 0o022 or before.st_size > 1048576):
                raise ToolContractError('extension_unsafe_module')
            content = stream.read(1048577)
            after = os.fstat(stream.fileno())
            identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
            if identity(before) != identity(after) or len(content) != before.st_size:
                raise ToolContractError('extension_unsafe_module')
        if hashlib.sha256(content).hexdigest() != extension.sha256:
            raise ToolContractError('extension_changed_module')
        return content
    except OSError:
        raise ToolContractError('extension_unsafe_module') from None


def extension_tools(extensions, *, root: Path, max_chars: int):
    """Construct worker-only Pydantic tools from exact pinned executable bytes.

    Each handler is async, receives validated keyword arguments, and returns a
    bounded string. Private exception details never become tool error wording.
    """
    from pydantic_ai import Tool
    from pydantic_ai.exceptions import ToolFailed

    tools, loaded = [], {}
    for extension in extensions:
        module_bytes(extension, forbidden=(root,))

        def build(spec):
            async def validate(ctx, **arguments):
                try:
                    validate_arguments(spec, arguments)
                except ToolContractError:
                    raise ToolFailed('Invalid arguments for the configured local tool.') from None

            async def invoke(**arguments):
                try:
                    validate_arguments(spec, arguments)
                    data = module_bytes(spec, forbidden=(root,))
                    key = (spec.module, spec.sha256)
                    if key not in loaded:
                        name = '_airlock_extension_' + spec.sha256
                        module = types.ModuleType(name)
                        module.__file__ = str(spec.module)
                        sys.modules[name] = module
                        try:
                            exec(compile(data, str(spec.module), 'exec'), module.__dict__)
                        except BaseException:
                            sys.modules.pop(name, None)
                            raise
                        loaded[key] = module
                    function = getattr(loaded[key], spec.handler, None)
                    if not inspect.iscoroutinefunction(function):
                        raise ToolContractError('extension_invalid_handler')
                    result = await function(**arguments)
                    if not isinstance(result, str) or len(result) > max_chars:
                        raise ToolContractError('extension_invalid_result')
                    return result
                except Exception:
                    raise ToolFailed('The configured local tool failed.') from None

            return Tool.from_schema(invoke, spec.name, spec.description, spec.parameters,
                                    sequential=True, args_validator=validate)

        tools.append(build(extension))
    return tools


def calculate_decimal(operation: Literal['add', 'subtract', 'multiply'], left: str, right: str,
                      max_chars: int) -> str:
    """Calculate exact plain decimals without file access, expressions or rounding."""
    if operation not in ('add', 'subtract', 'multiply') or any(
            not isinstance(value, str) or len(value) > max_chars or
            re.fullmatch(r'[+-]?[0-9]+(?:\.[0-9]+)?', value) is None for value in (left, right)):
        raise ToolContractError('calculator_invalid_arguments')
    with localcontext() as context:
        context.prec = len(left) + len(right) + 2
        a, b = Decimal(left), Decimal(right)
        return format(a+b if operation == 'add' else a-b if operation == 'subtract' else a*b, 'f')


def calculator_tool(max_chars: int):
    """Build the exact built-in calculator, with fixed private argument errors."""
    from pydantic_ai import Tool
    from pydantic_ai.exceptions import ToolFailed

    def calculate(operation: Literal['add', 'subtract', 'multiply'], left: StrictStr, right: StrictStr) -> str:
        """Add, subtract or multiply two exact plain decimal strings locally.

        Args:
            operation: One of add, subtract or multiply; no expressions or division.
            left: Signed ASCII decimal string without whitespace or exponent.
            right: Signed ASCII decimal string under the same local length limit.

        Returns:
            Exact fixed-point result without monetary rounding. Invalid operands
            produce a fixed local error; no files or commands are accessed.
        """
        try:
            return calculate_decimal(operation, left, right, max_chars)
        except ToolContractError:
            raise ToolFailed('Calculator requires bounded plain ASCII decimal strings and add, subtract or multiply.') from None

    return Tool(calculate, takes_ctx=False, sequential=True)
