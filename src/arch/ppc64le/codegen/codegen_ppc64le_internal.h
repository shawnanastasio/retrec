/**
 * Copyright 2021 Shawn Anastasio.
 *
 * This file is part of retrec.
 *
 * retrec is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * retrec is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with retrec.  If not, see <https://www.gnu.org/licenses/>.
 */

/**
 * This file define internal macros/helpers for ppc64le codegen routines
 */

#pragma once

/**
 * Helper macros for using relocations with local labels
 */
#define RELOC_DECLARE_LABEL(name) \
    do ctx.stream->add_aux(true, relocation{1, relocation::declare_label{name}}); while (0)
#define RELOC_DECLARE_LABEL_AFTER(name) \
    do ctx.stream->add_aux(true, relocation{1, relocation::declare_label_after{name}}); while (0)
#define RELOC_FIXUP_LABEL(name, pos) \
    do ctx.stream->add_aux(true, relocation{1, relocation::imm_rel_label_fixup{name, LabelPosition::pos}}); while (0)

// x-macro for all targets supported by the ppc64le backend
#define PPC64LE_ENUMERATE_SUPPORTED_TARGET_TRAITS(x, ...) \
    x(TargetTraitsX86_64, __VA_ARGS__)

// macro to instantiate codegen class for all traits
#define PPC64LE_INSTANTIATE_CODEGEN_FOR_ALL_TRAITS() \
    PPC64LE_ENUMERATE_SUPPORTED_TARGET_TRAITS(PPC64LE_INSTANTIATE_CODEGEN_FOR_TRAITS, _)
#define PPC64LE_INSTANTIATE_CODEGEN_FOR_TRAITS(x, ...) \
    template class retrec::codegen_ppc64le<x>;

// macro to instantiate a single method for all traits
#define PPC64LE_INSTANTIATE_CODGEN_MEMBER_(x, ret, name, ...) \
    template ret codegen_ppc64le<x>::name(__VA_ARGS__);
#define PPC64LE_INSTANTIATE_CODEGEN_MEMBER(ret, name, ...) \
    PPC64LE_ENUMERATE_SUPPORTED_TARGET_TRAITS(PPC64LE_INSTANTIATE_CODGEN_MEMBER_, ret, name, __VA_ARGS__)
