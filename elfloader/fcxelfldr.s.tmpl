# This is FcxElfLdr, the integrated ELF loader of the FreeChainXenon project
# Copyright (c) 2025 Aiden Isik
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

# When modifying this file: do not do ANYTHING which will result in relocations
# which need to be resolved by the linker. It won't work!
# Mainly, this means:
# - Don't attempt to get the addresses of labels
# - Don't try to reference anything outwith this file

.section .text

# Kernel function ordinal constants	
.set KERN_ORDINAL_VDDISPLAYFATALERROR, 0x1B2

# PE MZ magic ('M' 'Z')
.set PE_MZ_MAGIC, 0x4D5A

# PE new header magic ('P' 'E' 0x00 0x00)
.set PE_NEW_MAGIC_1, 0x5045
.set PE_NEW_MAGIC_2, 0x0000
	
# ELF magic (0x7F 'E' 'L' 'F')
.set ELF_MAGIC_1, 0x7F45
.set ELF_MAGIC_2, 0x4C46

# ELF section name (.elf, null terminated with 4 \0's)
.set PE_ELF_SECT_NAME_1, 0x2E65
.set PE_ELF_SECT_NAME_2, 0x6C66
.set PE_ELF_SECT_NAME_3, 0x0000
.set PE_ELF_SECT_NAME_4, 0x0000

# Constants used for ELF verification
.set ELF_CLASS_ELF32, 0x1
.set ELF_DATA_MSB, 0x2 # Big endian
.set ELF_VERSION, 0x1
.set ELF_TYPE_EXEC, 0x2
.set ELF_MACHINE_PPC, 0x14
.set ELF_HEADER_SIZE, 0x34

.global _start

	
# Read 32-bit little endian value and byte-swap it 
# IN: r4 == base address of little endian value
# IN: LR == address to return to
# OUT: r4 == read and byteswapped value
get32BitLittleEndian:
	# r5 == how many bytes to left shift each value read
	# r6 == working register used to store currently retrieved bytes
	# r7 == register to store current byte before shift
	
	li r5, 24 # Register storing how many bits to shift each value 

	# Most significant byte
	lbz r6, 3(r4)
	slw r6, r6, r5
	subi r5, r5, 8
	
	lbz r7, 2(r4)
	slw r7, r7, r5
	subi r5, r5, 8
	or r6, r6, r7
	
	lbz r7, 1(r4)
	slw r7, r7, r5
	or r6, r6, r7 

	# Least significant byte
	lbz r7, 0(r4)
	or r6, r6, r7
	
	mr r4, r6 # Final value
	blr


# Read 16-bit little endian value and byte-swap it 
# IN: r4 == base address of little endian value
# IN: LR == address to return to
# OUT: r4 == read and byteswapped value
get16BitLittleEndian:
	# r5 == how many bytes to left shift each value read
	# r6 == working register used to store currently retrieved bytes
	# r7 == register to store current byte before shift
	
	li r5, 8 # Register storing how many bits to shift each value 

	# Most significant byte
	lbz r6, 1(r4)
	slw r6, r6, r5
	subi r5, r5, 8

	# Least significant byte
	lbz r7, 0(r4)
	or r6, r6, r7
	
	mr r4, r6 # Final value
	blr

	
# If the function was not found, return 0 (set r3 = 0, then return) 
# IN: r12 == address to return to
# OUT: r3 == 0 
kernelFunctionNotFound:
	li r3, 0
	mtlr r12
	blr
	

# Getting function address by ordinal
# IN: r3 == ordinal number
# IN: LR == address to return to
# OUT: r3 == address of kernel function (or 0 if it could not be found)
getKernelFunctionAddrByOrdinal:
	mflr r12

	# Getting the address of the PE header
	lis r4, 0x8004
	ori r4, r4, 0x3C

	bl get32BitLittleEndian
	addis r4, r4, 0x8004 # Final address (RVA + kernel base address) 
	
	# Getting the address of the export directory table
	addi r4, r4, 0x78
	bl get32BitLittleEndian
	addis r4, r4, 0x8004 # Final address (RVA + kernel base address)
	
	# Making sure the ordinal exists (ordinal is not greater than or equal to export count)
	mr r8, r4 # Putting export directory table address into a register unused by get32BitLittleEndian
	addi r4, r4, 0x14 # Address of export count 

	bl get32BitLittleEndian # Get export count	
	cmpw r3, r4
	bgt kernelFunctionNotFound # Ordinal does not exist
	
	# Get address of the export address table, and retrieve the address of our function
	subi r3, r3, 1 # Converting ordinal into kernel EAT index

	addi r4, r8, 0x1C # Put address of RVA to EAT into r4
	bl get32BitLittleEndian # Get RVA to EAT
	addis r4, r4, 0x8004 # Address

	# Finally, read our address from the export address table and return it
	mulli r3, r3, 4 # Multiply index by 4 to get export offset
	add r4, r4, r3 # Add export offset to EAT address to get export address
	bl get32BitLittleEndian
	addis r3, r4, 0x8004 # Finally, the address of our function 
	
	mtlr r12
	blr


# Temporary error display until I learn how to exit without crashing the system
error:
	li r3, KERN_ORDINAL_VDDISPLAYFATALERROR
	bl getKernelFunctionAddrByOrdinal
	mtctr r3
	li r3, 0x0
	bctr

	
# Save non-volatile integer registers
saveNonVolatileRegisters:
	# Save registers
	std r2, -0x8(r1)
	std r13, -0x10(r1)
	std r14, -0x18(r1)
	std r15, -0x20(r1)
	std r16, -0x28(r1)
	std r17, -0x30(r1)
	std r18, -0x38(r1)
	std r19, -0x40(r1)
	std r20, -0x48(r1)
	std r21, -0x50(r1)
	std r22, -0x58(r1)
	std r23, -0x60(r1)
	std r24, -0x68(r1)
	std r25, -0x70(r1)
	std r26, -0x78(r1)
	std r27, -0x80(r1)
	std r28, -0x88(r1)
	std r29, -0x90(r1)
	std r30, -0x98(r1)
	std r31, -0xA0(r1)

	# Determine where the stack pointer should be moved to (16-byte alignment down)
	subi r14, r1, 0xA8 # Make sure we have at LEAST 8 bytes below all the other values
	lis r15, 0xFFFF
	ori r15, r15, 0xFFF0
	and r14, r14, r15

	# Save the stack pointer, then update it
	std r1, -0x8(r14)
	mr r1, r14

	# Done
	blr


# Restore non-volatile integer registers
restoreNonVolatileRegisters:
	# Restore the old stack pointer
	ld r1, -0x8(r1)
	
	# Restore registers
	ld r2, -0x8(r1)
	ld r13, -0x10(r1)
	ld r14, -0x18(r1)
	ld r15, -0x20(r1)
	ld r16, -0x28(r1)
	ld r17, -0x30(r1)
	ld r18, -0x38(r1)
	ld r19, -0x40(r1)
	ld r20, -0x48(r1)
	ld r21, -0x50(r1)
	ld r22, -0x58(r1)
	ld r23, -0x60(r1)
	ld r24, -0x68(r1)
	ld r25, -0x70(r1)
	ld r26, -0x78(r1)
	ld r27, -0x80(r1)
	ld r28, -0x88(r1)
	ld r29, -0x90(r1)
	ld r30, -0x98(r1)
	ld r31, -0xA0(r1)

	# Done
	blr


# Get size of pages from address
# IN: r3 == address
# IN: LR == address to return to
# OUT: r3 == page size
# OUT: r4 == page size mask
getCurrentPageSize:
	lis r4, 0x9000
	cmpl cr0, r3, r4
	bge currentPageSizeSmall

	# Big (0x10000) pages
	lis r3, 0x1
	lis r4, 0xFFFF
	blr

	# Small (0x1000) pages
currentPageSizeSmall:
	li r3, 0x1000
	lis r4, 0xFFFF
	ori r4, r4, 0xF000
	blr
	
	
# Entry point
_start:
	# We want this ELF loader to be completely transparent. In other words,
	# make sure to keep the registers and stack the same before and after execution

	# Save integer registers
	# (this code needs to be duplicated as we need to be able to save LR
	# before calling anything else, without overwriting any registers)
	std r2, -0x8(r1)
	std r3, -0x10(r1)
	std r4, -0x18(r1)
	std r5, -0x20(r1)
	std r6, -0x28(r1)
	std r7, -0x30(r1)
	std r8, -0x38(r1)
	std r9, -0x40(r1)
	std r10, -0x48(r1)
	std r11, -0x50(r1)
	std r12, -0x58(r1)
	std r13, -0x60(r1)
	std r14, -0x68(r1)
	std r15, -0x70(r1)
	std r16, -0x78(r1)
	std r17, -0x80(r1)
	std r18, -0x88(r1)
	std r19, -0x90(r1)
	std r20, -0x98(r1)
	std r21, -0xA0(r1)
	std r22, -0xA8(r1)
	std r23, -0xB0(r1)
	std r24, -0xB8(r1)
	std r25, -0xC0(r1)
	std r26, -0xC8(r1)
	std r27, -0xD0(r1)
	std r28, -0xD8(r1)
	std r29, -0xE0(r1)
	std r30, -0xE8(r1)
	std r31, -0xF0(r1)

	# Save the link register
	mflr r2
	std r2, -0xF8(r1)

	# Determine where the stack pointer should be moved to (16-byte alignment down)
	subi r2, r1, 0x108 # Make sure we have at LEAST 8 bytes below all the other values
	lis r3, 0xFFFF
	ori r3, r3, 0xFFF0
	and r2, r2, r3

	# Save the stack pointer, then update it
	std r1, -0x8(r2)
	mr r1, r2

	# Now start the loading process
	b loadElf


# Responsible for calling the different functions to load the ELF
loadElf:
	bl findElfSection # Returns address to beginning of ELF in r3
	bl verifyElf # Takes address to ELF in r3, only returns if ELF is valid
	b executeElf # Takes address to ELF in r3, never returns


# Locates the ELF section inside the currently loaded PE
# IN: LR == Address to return to
# OUT: r3 == Address of ELF in memory
findElfSection:
	# Save the link register
	mflr r12

	# Save all non-volatile integer registers
	bl saveNonVolatileRegisters
	
	# Find the PE header

	bl $+4 # Put current execution address into link register
	mflr r3 # And pass it along
	mr r14, r3 # Also store it for later use (will become PE header address)
	bl getCurrentPageSize

	# r3 now contains page size, r4 contains page size mask. Move them to non-volatile registers.
	mr r15, r3
	mr r16, r4
	
	# Get the address of the PE header
findPeHeaderLoop:
	# Mask the current address to get the start of this page
	and r14, r14, r16
	
	# Save current base address
	mr r18, r14
	
	# Check for "MZ" magic. If we don't have it, PE header is not here.
	lhz r17, 0(r14) 
	cmpli cr0, r17, PE_MZ_MAGIC
	bne nextPageFindPeHeader

	# Check if offset to new header is valid. If not, PE is not here.
	addi r4, r14, 0x3C
	bl get32BitLittleEndian

	cmpli cr0, r4, 0x40 # If relative offset < 0x40, it's invalid.
	blt nextPageFindPeHeader

	cmpl cr0, r4, r15 # If relative offset > page size, it's invalid.
	bge nextPageFindPeHeader

	# Check if new header "PE\0\0" magic is valid. If it is, we found the PE header.

	# Load in the magic we have on record
	lis r3, PE_NEW_MAGIC_1
	ori r3, r3, PE_NEW_MAGIC_2

	# Load in the magic in memory
	add r14, r14, r4 # Transform new header offset to address
	lwz r5, 0(r14)

	# Compare them
	cmpl cr0, r3, r5
	beq foundPeHeader

nextPageFindPeHeader:
	subf r14, r3, r14
	b findPeHeaderLoop

foundPeHeader:
	# Get number of sections in the PE and store that in r15
	addi r4, r14, 0x6
	bl get16BitLittleEndian
	mr r15, r4

	# Search section table until we find the ".elf" section
	addi r16, r14, 0xF8 # Address of beginning of section table
	mtctr r15 # Load the section count into CTR for the loop

searchSectionTableLoop:
	# Put address of current section entry into r15
	mfctr r15
	subi r15, r15, 1
	mulli r15, r15, 0x28 # Multiply entry index by size of entry
	add r15, r15, r16 # Add address of section table

	# Compare the name of the current entry to our stored ".elf\0\0\0\0"

	# Load in the stored name
	lis r3, PE_ELF_SECT_NAME_1
	ori r3, r3, PE_ELF_SECT_NAME_2
	slwi r3, r3, 31
	oris r3, r3, PE_ELF_SECT_NAME_3
	ori r3, r3, PE_ELF_SECT_NAME_4

	# Load in the current section name
	ld r4, 0(r15)

	# Compare them. If they're equal, we found the section
	cmp cr0, r3, r4
	beq foundElfSection

	# Check next entry
	bdnz searchSectionTableLoop

	# If we get here, there is no ".elf" section. Abort.
	b error
	
foundElfSection:
	# Base of current section entry is currently in r15
	# Get the RVA from the entry, turn it into an address, and put it in r3
	
	addi r4, r15, 0xC # 0xC == offset in entry of RVA
	bl get32BitLittleEndian
	add r3, r18, r4 # Base address + RVA
	
	# Restore non-volatile integer registers
	bl restoreNonVolatileRegisters

	# Restore the link register and return
	mtlr r12
	blr


# Verifies the embedded ELF file
# IN: r3 == address in memory of the ELF
# IN: LR == address to return to
verifyElf:	
	# Load in the stored magic
	lis r4, ELF_MAGIC_1
	ori r4, r4, ELF_MAGIC_2

	# Load in the magic in memory
	lwz r5, 0(r3)

	# Compare them. If they don't match, it's not an ELF. Abort.
	cmpl cr0, r4, r5
	bne error

	# Check ELF class (should be ELF32 for 32-bit addressing)
	lbz r4, 0x4(r3)
	cmpli cr0, r4, ELF_CLASS_ELF32
	bne error

	# Check ELF endianness (should be big endian, for obvious reasons)
	lbz r4, 0x5(r3)
	cmpli cr0, r4, ELF_DATA_MSB
	bne error

	# Check ELF version (should be 0x1, anything else is invalid)
	lbz r4, 0x6(r3)
	cmpli cr0, r4, ELF_VERSION
	bne error
	
	# Check ELF type (should be executable, non relocatable, EXEC)
	lhz r4, 0x10(r3)
	cmpli cr0, r4, ELF_TYPE_EXEC
	bne error

	# Check ELF machine (expecting PowerPC)
	lhz r4, 0x12(r3)
	cmpli cr0, r4, ELF_MACHINE_PPC
	bne error

	# Check header size (just an additional check to ensure this is an ELF32)
	lhz r4, 0x28(r3)
	cmpli cr0, r4, ELF_HEADER_SIZE
	bne error
	
	# ELF is valid!
	blr


# Runs the embedded ELF file
# IN: r3 == address of ELF
executeElf:
	# Load in the entry point address and put it in CTR, ready to branch	
	lwz r3, 0x18(r3)
	mtctr r3

	# Restore the old stack pointer
	ld r1, -0x8(r1)
	
	# Restore the link register
	ld r2, -0xF8(r1)
	mtlr r2
	
	# Restore integer registers
	ld r2, -0x8(r1)
	ld r3, -0x10(r1)
	ld r4, -0x18(r1)
	ld r5, -0x20(r1)
	ld r6, -0x28(r1)
	ld r7, -0x30(r1)
	ld r8, -0x38(r1)
	ld r9, -0x40(r1)
	ld r10, -0x48(r1)
	ld r11, -0x50(r1)
	ld r12, -0x58(r1)
	ld r13, -0x60(r1)
	ld r14, -0x68(r1)
	ld r15, -0x70(r1)
	ld r16, -0x78(r1)
	ld r17, -0x80(r1)
	ld r18, -0x88(r1)
	ld r19, -0x90(r1)
	ld r20, -0x98(r1)
	ld r21, -0xA0(r1)
	ld r22, -0xA8(r1)
	ld r23, -0xB0(r1)
	ld r24, -0xB8(r1)
	ld r25, -0xC0(r1)
	ld r26, -0xC8(r1)
	ld r27, -0xD0(r1)
	ld r28, -0xD8(r1)
	ld r29, -0xE0(r1)
	ld r30, -0xE8(r1)
	ld r31, -0xF0(r1)
	
	# Finally, jump to the entry point and run the ELF!
	bctr

	
# Include the ELF in our output PE file
.section .elf
.incbin "EXEC_NAME"
