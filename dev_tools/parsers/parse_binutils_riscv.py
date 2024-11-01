""" Parse riscv isa definitions directly from binutils """
import os
from typing import List, Dict, Set, Tuple
import csv
from dataclasses import dataclass
from collections import Counter
import yaml


VECTOR_EXTS = [
    "INSN_CLASS_V",
    "INSN_CLASS_ZVBB",
    "INSN_CLASS_ZVBC",
    "INSN_CLASS_ZVKNED",
    "INSN_CLASS_ZVKN",
    "INSN_CLASS_ZVKS",
    "INSN_CLASS_ZVEF",
]


@dataclass
class PatternInfo:
    """ Fields and asm format of a given instruction. """
    field_list: List[str]
    asm: str


def get_pattern_info() -> Dict[str, PatternInfo]:
    """ Get a dict mapping patterns to fields/asm formats. """
    pattern_info_dict: Dict[str, PatternInfo] = {}

    # int reg -> int reg patterns
    pattern_info_dict["BLANK"] = PatternInfo(["funct25", "opcode"], "OPC")
    pattern_info_dict["d,s,t"] = PatternInfo(
        ["funct10", "rs1", "rs2", "rd", "opcode"], "OPC rd, rs1, rs2"
    )
    pattern_info_dict["d,s"] = PatternInfo(
        ["funct10", "funct5", "rs1", "rd", "opcode"], "OPC rd, rs1"
    )
    # j is a sign extended immediate
    pattern_info_dict["d,s,j"] = PatternInfo(
        ["funct3", "i_imm12", "rs1", "rd", "opcode"], "OPC rd, rs1, i_imm12"
    )
    # < is shift amount
    pattern_info_dict["d,s,<"] = PatternInfo(
        ["funct3", "i_imm7", "i_shamt5", "rs1", "rd", "opcode"], "OPC rd, rs1, i_shamt5"
    )
    # > is shift amount
    pattern_info_dict["d,s,>"] = PatternInfo(
        ["funct3", "i_imm7", "i_shamt5", "rs1", "rd", "opcode"], "OPC rd, rs1, i_shamt5"
    )
    # y is 2 bit imm
    pattern_info_dict["d,s,t,y"] = PatternInfo(
        ["funct5", "i_imm3", "i_shamt2", "rs2", "rs1", "rd", "opcode"],
        "OPC rd, rs1, rs2, i_shamt2",
    )

    pattern_info_dict["s,t"] = PatternInfo(
        ["funct10", "funct5", "rs2", "rs1", "opcode"], "OPC rs1, rs2"
    )

    # Vec -> Int patterns
    pattern_info_dict["d,Vt"] = PatternInfo(
        ["funct10", "funct5", "rd", "vrs2", "opcode"], "OPC rd, vrs2"
    )

    # Imm -> Vec patterns
    # Vi is 5 bit signed imm
    pattern_info_dict["Vd,Vt,Vi"] = PatternInfo(
        ["funct10", "vd", "vrs2", "i_imm5", "opcode"], "OPC vd, vrs2, i_imm5"
    )

    pattern_info_dict["Vd,Vt,Vi,V0"] = PatternInfo(
        ["funct5", "vmd", "vrs2", "i_imm5", "vmask", "opcode"],
        "OPC vmd, vrs2, i_imm5, vmask",
    )

    # Vj is 5 bit unsigned imm
    pattern_info_dict["Vd,Vt,Vj"] = PatternInfo(
        ["funct10", "vd", "vrs2", "i_shamt5", "opcode"], "OPC vd, vrs2, i_shamt5"
    )

    # Int -> Vec patterns
    pattern_info_dict["Vd,s"] = PatternInfo(
        ["funct10", "funct5", "vd", "rs1", "opcode"], "OPC vd, rs1"
    )

    # Vec, Int -> Vec patterns
    pattern_info_dict["Vd,Vt,s"] = PatternInfo(
        ["funct10", "vd", "vrs2", "rs1", "opcode"], "OPC vd, vrs2, rs1"
    )

    pattern_info_dict["Vd,s,Vt"] = PatternInfo(
        ["funct10", "vd", "vrs2", "rs1", "opcode"], "OPC vd, rs1, vrs2"
    )

    # Vec, Float -> Vec patterns
    pattern_info_dict["Vd,Vt,S"] = PatternInfo(
        ["funct10", "vd", "vrs2", "frs1", "opcode"], "OPC vd, vrs2, frs1"
    )
    pattern_info_dict["Vd,S,Vt"] = PatternInfo(
        ["funct10", "vd", "vrs2", "frs1", "opcode"],
        "OPC vd, frs1, vrs2",
    )

    # Float -> Vec patterns
    pattern_info_dict["Vd,S"] = PatternInfo(
        ["funct10", "funct5", "vd", "frs1", "opcode"], "OPC vd, frs1"
    )

    # Vec -> Float patterns
    pattern_info_dict["D,Vt"] = PatternInfo(
        ["funct10", "funct5", "frd", "vrs2", "opcode"], "OPC frd, vrs2"
    )

    # Vec -> Vec patterns
    pattern_info_dict["Vd,Vs"] = PatternInfo(
        ["funct10", "funct5", "vd", "vrs1", "opcode"], "OPC vd, vrs1"
    )
    pattern_info_dict["Vd,Vt,Vs"] = PatternInfo(
        ["funct10", "vd", "vrs2", "vrs1", "opcode"], "OPC vd, vrs2, vrs1"
    )
    pattern_info_dict["Vd,Vt,s"] = PatternInfo(
        ["funct10", "vd", "vrs2", "rs1", "opcode"],
        "OPC vd, vrs2, rs1",
    )
    pattern_info_dict["Vd,Vs,Vt"] = PatternInfo(
        ["funct10", "vd", "vrs1", "vrs2", "opcode"],
        "OPC vd, vrs1, vrs2",
    )
    pattern_info_dict["Vd,Vt"] = PatternInfo(
        ["funct10", "funct5", "vd", "vrs2", "opcode"], "OPC vd, vrs2"
    )
    pattern_info_dict["Vd,Vt,Vj"] = PatternInfo(
        ["funct10", "vd", "vrs2", "i_shamt5", "opcode"],
        "OPC vd, vrs2, i_shamt5",
    )

    pattern_info_dict["Vd,Vt,Vk"] = PatternInfo(
        ["funct10", "vd", "vrs2", "ioff_imm5", "opcode"],
        "OPC vd, vrs2, ioff_imm5",
    )

    pattern_info_dict["Vd,Vu"] = PatternInfo(
        ["funct10", "funct5", "vd", "vrs1", "opcode"],
        "OPC vd, vrs1",
    )

    pattern_info_dict["Vv"] = PatternInfo(
        ["funct20", "vd", "opcode"],
        "OPC vd",
    )

    pattern_info_dict["Vd"] = PatternInfo(
        ["funct20", "vd", "opcode"],
        "OPC vd",
    )

    pattern_info_dict["Vd,Vi"] = PatternInfo(
        ["funct10", "funct5", "vd", "i_imm5", "opcode"],
        "OPC vd, i_imm5",
    )

    pattern_info_dict["Vd,Vi"] = PatternInfo(
        ["funct10", "funct5", "vd", "i_imm5", "opcode"],
        "OPC vd, i_imm5",
    )

    pattern_info_dict["Vd,Vt,Vl"] = PatternInfo(
        ["funct5", "funct4", "vd", "vrs2", "i_imm6", "opcode"],
        "OPC vd, vrs2, i_imm6",
    )

    pattern_info_dict["Vd,Vt,Vs,V0"] = PatternInfo(
        ["funct5", "vmd", "vrs2", "vrs1", "vmask", "opcode"],
        "OPC vmd, vrs1, vrs2, vmask",
    )

    pattern_info_dict["Vd,Vt,s,V0"] = PatternInfo(
        ["funct5", "vmd", "vrs2", "rs1", "vmask", "opcode"],
        "OPC vmd, vrs2, rs1, vmask",
    )

    # Float
    pattern_info_dict["Vd,Vt,S,V0"] = PatternInfo(
        ["funct5", "vmd", "vrs2", "frs1", "vmask", "opcode"],
        "OPC vmd, vrs2, frs1, vmask",
    )

    pattern_info_dict["d,Vt"] = PatternInfo(
        ["funct10", "funct5", "rd", "vrs2", "opcode"],
        "OPC rd, vrs2",
    )

    pattern_info_dict["d,VtVm"] = PatternInfo(
        ["funct10", "rd", "vrs2", "vmask", "opcode"],
        "OPC rd, vrs2, vmask.t",
    )

    # Add masked variants
    masked_patterns: Dict[str, PatternInfo] = {}
    for pattern, pattern_info in pattern_info_dict.items():
        if pattern.startswith("Vd"):
            field_list = pattern_info.field_list + ["vmask"]
            # Field list is 37 bytes, eliminate funct5 or reduce funct10 if possible.
            if "funct5" in field_list:
                field_list.remove("funct5")
            elif "funct10" in field_list:
                field_list.remove("funct10")
                field_list.append("funct5")
            elif "funct20" in field_list:
                field_list.remove("funct20")
                field_list.append("funct10")
                field_list.append("funct5")

            field_list = ["vmd" if field == "vd" else field for field in field_list]
            asm = (pattern_info.asm + ", vmask.t").replace("vd", "vmd", 1)

            masked_patterns[pattern + "Vm"] = PatternInfo(field_list, asm)

    pattern_info_dict |= masked_patterns

    # Add widening variants
    widening_patterns: Dict[str, PatternInfo] = {}
    for pattern, pattern_info in pattern_info_dict.items():
        if pattern.startswith("Vd"):
            # Wide output
            field_list = [
                "vdmd" if field == "vmd" else ("vdd" if field == "vd" else field)
                for field in pattern_info.field_list
            ]
            asm = pattern_info.asm.replace("vd", "vdd", 1).replace("vmd", "vdmd", 1)
            widening_patterns[pattern + "_wide_out"] = PatternInfo(field_list, asm)

            # Wide input + output
            winout_field_list = [
                "vdrs2" if field == "vrs2" else field for field in field_list
            ]
            winout_asm = asm.replace("vrs2", "vdrs2", 1)
            widening_patterns[pattern + "_wide_in_wide_out"] = PatternInfo(
                winout_field_list, winout_asm
            )

            # Wide input
            field_list = [
                "vnmd" if field == "vmd" else ("vnd" if field == "vd" else field)
                for field in pattern_info.field_list
            ]
            win_field_list = [
                "vdrs2" if field == "vrs2" else field for field in field_list
            ]
            win_asm = pattern_info.asm.replace("vd", "vnd", 1).replace("vmd", "vnmd", 1)
            win_asm = win_asm.replace("vrs2", "vdrs2", 1)
            widening_patterns[pattern + "_wide_in"] = PatternInfo(
                win_field_list, win_asm
            )

    pattern_info_dict |= widening_patterns

    return pattern_info_dict


@dataclass
class InsnInfo:
    """ Instruction info. """
    name: str
    ext: str
    format: Tuple[str, str]


def filter_insns(
    insns: List[str],
    extensions: List[str],
    formats: List[str],
    ignored_insns: Set[str],
    filtered_extensions: Set[str],
    filtered_formats: Set[str],
) -> Tuple[List[InsnInfo], List[InsnInfo]]:
    """ Filter out unsupported instructions. """
    filtered_insns: List[InsnInfo] = []
    missing_pattern_insns: List[InsnInfo] = []
    for insn, ext, fmt in zip(insns, extensions, formats):
        sanitized_format = (
            fmt.replace(",", "-")
            .replace("(", "-")
            .replace(")", "-")
            .replace("<", "ls")
            .replace(">", "rs")
        )

        if (
            ext in filtered_extensions
            and fmt not in filtered_formats
            and insn not in ignored_insns
        ):
            missing_pattern_insns.append(
                InsnInfo(insn, ext, (fmt, sanitized_format))
            )
        if (
            ext in filtered_extensions
            and fmt in filtered_formats
            and insn not in ignored_insns
        ):
            filtered_insns.append(InsnInfo(insn, ext, (fmt, sanitized_format)))

    return filtered_insns, missing_pattern_insns


def parse_binutils():
    """ Parse the binutils source files. """
    with open("../binutils-files/2_40-release-hash-32778522c7d/riscv-opc.c", "r", encoding='UTF-8') as stream:
        raw_file = stream.read()

    split = raw_file.splitlines()

    minimal_lines = filter(lambda line: (line.startswith("{") and len(line) > 1), split)

    split_lines = [line.split("{")[1].split("}")[0] for line in minimal_lines]

    insns = [
        row[0]
        for row in csv.reader(
            split_lines, quotechar='"', quoting=csv.QUOTE_ALL, skipinitialspace=True
        )
    ]
    extensions = [
        row[2]
        for row in csv.reader(
            split_lines, quotechar='"', quoting=csv.QUOTE_ALL, skipinitialspace=True
        )
    ]
    formats = [
        row[3]
        for row in csv.reader(
            split_lines, quotechar='"', quoting=csv.QUOTE_ALL, skipinitialspace=True
        )
    ]
    tags = [
        row[-1]
        for row in csv.reader(
            split_lines, quotechar='"', quoting=csv.QUOTE_ALL, skipinitialspace=True
        )
    ]

    # Mark alias insns
    for i, tag in enumerate(tags):
        if "INSN_ALIAS" in tag:
            formats[i] = formats[i] + "_alias"

    # Generate unmasked variants for all masked vector insns
    unmasked_insns: List[str] = []
    unmasked_formats: List[str] = []
    for insn, ext, form in zip(insns, extensions, formats):
        if ext in VECTOR_EXTS and form.endswith("Vm"):
            unmasked_insns.append(insn)
            unmasked_formats.append(form[:-2])

    for ext in VECTOR_EXTS:
        insns.extend(unmasked_insns)
        extensions.extend([ext for _ in unmasked_insns])
        formats.extend(unmasked_formats)

    # Mark widening insns
    for i, (insn, ext, form) in enumerate(zip(insns, extensions, formats)):
        if ext in VECTOR_EXTS and insn.startswith("vw") and ".w" in insn:
            formats[i] = formats[i] + "_wide_in_wide_out"
        elif ext in VECTOR_EXTS and insn.startswith("vw"):
            formats[i] = formats[i] + "_wide_in"
        elif ext in VECTOR_EXTS and ".w" in insn:
            formats[i] = formats[i] + "_wide_in"

    os.makedirs(os.path.dirname("./gen/all_insns.txt"), exist_ok=True)

    with open("gen/all_insns.txt", "w", encoding='UTF-8') as stream:
        for item in sorted(list(set(insns))):
            stream.writelines(item + "\n")

    with open("gen/all_extensions.txt", "w", encoding='UTF-8') as stream:
        for item in sorted(list(set(extensions))):
            stream.writelines(item + "\n")

    with open("gen/all_formats.txt", "w", encoding='UTF-8') as stream:
        for item in sorted(list(set(formats))):
            stream.writelines(item + "\n")

    return insns, extensions, formats


def print_filter_stats(
    filtered_insns: List[InsnInfo], missing_pattern_insns: List[InsnInfo]
):
    """ Print some stats about the implemented/unsupported instructions. """
    imp_insns = {insn.name for insn in filtered_insns}
    imp_ext = {insn.ext for insn in filtered_insns}
    imp_format = {insn.format for insn in filtered_insns}

    print()
    print("Implemented insns:", len(imp_insns))
    print("Implemented extensions:", len(imp_ext))
    print("Implemented formats:", len(imp_format))

    unimp_insns = {insn.name for insn in missing_pattern_insns}
    unimp_format = {insn.format[0] for insn in missing_pattern_insns}
    unimp_alias_format = {insn.format[0] for insn in missing_pattern_insns if any(["_alias" in fmt for fmt in insn.format]) }

    print()
    print("Formats missing pattern:", len(unimp_format))
    print("Insns missing pattern:", len(unimp_insns))
    print("Alias insns missing pattern:", len(unimp_alias_format))

    unimp_format_counter = Counter(
        [insn.format for insn in missing_pattern_insns if insn.name not in imp_insns]
    )

    print()
    print("Top unimplemented formats:")
    print(unimp_format_counter)


def main():
    """ Perform parsing and store outputs in ./gen """
    insns, extensions, formats = parse_binutils()

    filtered_extensions = set(
        VECTOR_EXTS
    )
    filtered_formats = set(get_pattern_info().keys())
    ignored_insns = set(
        [
            # These are special cases.
            "vzext.vf8",
            "vsext.vf8",
            "vrgatherei16.vv",
            "vzext.vf2",
            "vzext.vf4",
            "vsext.vf2",
            "vsext.vf4",
            "vmv2r.v",
            "vmv4r.v",
            "vmv8r.v",
            "vmsgeu.vx",
            "vmsge.vx",
        ]
    )

    print("Ignored insns:", ignored_insns)

    formats = [format if format != "" else "BLANK" for format in formats]

    filtered_insns, missing_pattern_insns = filter_insns(
        insns, extensions, formats, ignored_insns, filtered_extensions, filtered_formats
    )

    print_filter_stats(filtered_insns, missing_pattern_insns)

    instruction_list: List[Dict[str, str]] = []
    insn_names: List[str] = []

    seen: Set[Tuple[str, str]] = set()

    for insn in filtered_insns:
        fmt = insn.format[1]

        if (insn.name, fmt) in seen:
            continue

        seen.add((insn.name, fmt))

        if insn.ext in VECTOR_EXTS:
            insn_name = f"{insn.name}_{'V1' if ('Vm' in fmt) else 'V0'}".upper()
        else:
            insn_name = f"{insn.name}_V0".upper()

        # TODO Memory operands
        insn_names.append(insn_name)
        instruction_list.append(
            {
                "Name": insn_name,
                "Format": fmt + "_parsed",
                # "Extension": extensions[i],
                "Mnemonic": insn.name.upper(),
                "Opcode": "0",
                "Description": "Auto parsed from binutils. Opcode is dummy data",
            }
        )

    insn_names = sorted(insn_names)

    assert len(insn_names) == len(set(insn_names)), "Duplicate insn name detected!"

    with open("gen/instruction.yaml", "w", encoding='UTF-8') as stream:
        yaml.dump(instruction_list, stream, sort_keys=True)

    # Generate instruction format yaml placeholder to be filled out
    instruction_formats: List[Dict[str, str | List[str]]] = []

    pattern_info = get_pattern_info()

    for fmt in {insn.format for insn in filtered_insns}:
        instruction_formats.append(
            {
                "Name": fmt[1] + "_parsed",
                "Fields": pattern_info[fmt[0]].field_list,
                "Assembly": pattern_info[fmt[0]].asm,
            }
        )

    instruction_formats = sorted(instruction_formats, key=lambda d: d["Name"])

    # Output files
    with open("gen/instruction_format.yaml", "w", encoding='UTF-8') as stream:
        yaml.dump(instruction_formats, stream, sort_keys=True)

    with open("gen/implemented_insns.txt", "w", encoding='UTF-8') as stream:
        unmasked_vector_ops = [
            name
            for name in insn_names
            if ("_V0" in name and "VM" not in name) and name.startswith("V")
        ]

        masked_vector_ops = [
            name for name in insn_names if ("_V1" in name or "VM" in name) and name.startswith("V")
        ]
        stream.writelines(
            [
                f"All: {','.join(insn_names)}\n",
                "\n",
                f"VNOMASK: {','.join(unmasked_vector_ops)}\n",
                "\n",
                f"VMASK: {','.join(masked_vector_ops)}",
                "\n",
            ]
        )

    with open("gen/unimplemented_insns.txt", "w", encoding='UTF-8') as stream:
        stream.writelines(
            [
                "\n".join(
                    [
                        ",".join([insn.name, insn.ext, insn.format[0], insn.format[1]])
                        for insn in missing_pattern_insns
                    ]
                )
            ]
        )

    # Generate final stats
    num_insns_implemented = len({insn.name for insn in filtered_insns})
    num_insns_total = len({insn.name for insn in filtered_insns}) + \
        len({insn.name for insn in missing_pattern_insns})

    print( \
        f"Implemented support for {num_insns_implemented}/{num_insns_total} instructions "
        f"({len(filtered_insns)}/{len(set(insns))} of those with valid extensions)"
    )


if __name__ == "__main__":
    main()
