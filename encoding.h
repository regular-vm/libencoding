#include <cassert>
#include <cstdint>
#include <iostream>
#include <type_traits>
#include <unordered_map>
#include <utility>
#include <variant>

namespace regular {

enum class Opcode : uint8_t {
	NOP,
	ADD,
	SUB,
	AND,
	ORR,
	XOR,
	NOT,
	LSH,
	ASH,
	TCU,
	TCS,
	SET,
	MOV,
	LDW,
	STW,
	LDB,
	STB,
};

std::unordered_map opcode_names = {
    std::make_pair(Opcode::NOP, "nop"),
    std::make_pair(Opcode::ADD, "add"),
    std::make_pair(Opcode::SUB, "sub"),
    std::make_pair(Opcode::AND, "and"),
    std::make_pair(Opcode::ORR, "orr"),
    std::make_pair(Opcode::XOR, "xor"),
    std::make_pair(Opcode::NOT, "not"),
    std::make_pair(Opcode::LSH, "lsh"),
    std::make_pair(Opcode::ASH, "ash"),
    std::make_pair(Opcode::TCU, "tcu"),
    std::make_pair(Opcode::TCS, "tcs"),
    std::make_pair(Opcode::SET, "set"),
    std::make_pair(Opcode::MOV, "mov"),
    std::make_pair(Opcode::LDW, "ldw"),
    std::make_pair(Opcode::STW, "stw"),
    std::make_pair(Opcode::LDB, "ldb"),
    std::make_pair(Opcode::STB, "stb"),
};

enum class Register : uint8_t {
	R0,
	PC = 0,
	R1,
	R2,
	R3,
	R4,
	R5,
	R6,
	R7,
	R8,
	R9,
	R10,
	R11,
	R12,
	R13,
	R14,
	R15,
	R16,
	R17,
	R18,
	R19,
	R20,
	R21,
	R22,
	R23,
	R24,
	R25,
	R26,
	R27,
	R28,
	R29,
	R30,
	AT = 30,
	R31,
	SP = 31,
	_count,
};

std::unordered_map register_names = {
    std::make_pair(Register::R0, "r0"),
    std::make_pair(Register::PC, "pc"),
    std::make_pair(Register::R1, "r1"),
    std::make_pair(Register::R2, "r2"),
    std::make_pair(Register::R3, "r3"),
    std::make_pair(Register::R4, "r4"),
    std::make_pair(Register::R5, "r5"),
    std::make_pair(Register::R6, "r6"),
    std::make_pair(Register::R7, "r7"),
    std::make_pair(Register::R8, "r8"),
    std::make_pair(Register::R9, "r9"),
    std::make_pair(Register::R10, "r10"),
    std::make_pair(Register::R11, "r11"),
    std::make_pair(Register::R12, "r12"),
    std::make_pair(Register::R13, "r13"),
    std::make_pair(Register::R14, "r14"),
    std::make_pair(Register::R15, "r15"),
    std::make_pair(Register::R16, "r16"),
    std::make_pair(Register::R17, "r17"),
    std::make_pair(Register::R18, "r18"),
    std::make_pair(Register::R19, "r19"),
    std::make_pair(Register::R20, "r20"),
    std::make_pair(Register::R21, "r21"),
    std::make_pair(Register::R22, "r22"),
    std::make_pair(Register::R23, "r23"),
    std::make_pair(Register::R24, "r24"),
    std::make_pair(Register::R25, "r25"),
    std::make_pair(Register::R26, "r26"),
    std::make_pair(Register::R27, "r27"),
    std::make_pair(Register::R28, "r28"),
    std::make_pair(Register::R29, "r29"),
    std::make_pair(Register::R30, "r30"),
    std::make_pair(Register::AT, "at"),
    std::make_pair(Register::R31, "r31"),
    std::make_pair(Register::SP, "sp"),
};

enum class OperandLayout {
	_,
	REG_IMM,
	REG_REG,
	REG_REG_REG,
};

template <OperandLayout _OperandLayout>
struct Operands;

template <Opcode _Opcode, typename _Operands>
class Instruction;

using NoOperands = Operands<OperandLayout::_>;
using RegImmOperands = Operands<OperandLayout::REG_IMM>;
using RegRegOperands = Operands<OperandLayout::REG_REG>;
using RegRegRegOperands = Operands<OperandLayout::REG_REG_REG>;

using NopInstruction = Instruction<Opcode::NOP, NoOperands>;
using AddInstruction = Instruction<Opcode::ADD, RegRegRegOperands>;
using SubInstruction = Instruction<Opcode::SUB, RegRegRegOperands>;
using AndInstruction = Instruction<Opcode::AND, RegRegRegOperands>;
using OrrInstruction = Instruction<Opcode::ORR, RegRegRegOperands>;
using XorInstruction = Instruction<Opcode::XOR, RegRegRegOperands>;
using NotInstruction = Instruction<Opcode::NOT, RegRegOperands>;
using LshInstruction = Instruction<Opcode::LSH, RegRegRegOperands>;
using AshInstruction = Instruction<Opcode::ASH, RegRegRegOperands>;
using TcuInstruction = Instruction<Opcode::TCU, RegRegRegOperands>;
using TcsInstruction = Instruction<Opcode::TCS, RegRegRegOperands>;
using SetInstruction = Instruction<Opcode::SET, RegImmOperands>;
using MovInstruction = Instruction<Opcode::MOV, RegRegOperands>;
using LdwInstruction = Instruction<Opcode::LDW, RegRegOperands>;
using StwInstruction = Instruction<Opcode::STW, RegRegOperands>;
using LdbInstruction = Instruction<Opcode::LDB, RegRegOperands>;
using StbInstruction = Instruction<Opcode::STB, RegRegOperands>;

using InstructionTypes = std::variant<
    NopInstruction,
    AddInstruction,
    SubInstruction,
    AndInstruction,
    OrrInstruction,
    XorInstruction,
    NotInstruction,
    LshInstruction,
    AshInstruction,
    TcuInstruction,
    TcsInstruction,
    SetInstruction,
    MovInstruction,
    LdwInstruction,
    StwInstruction,
    LdbInstruction,
    StbInstruction>;

template <OperandLayout _OperandLayout>
struct Operands {
  public:
	static const regular::OperandLayout OperandLayout = _OperandLayout;

  private:
	explicit Operands(uint32_t encoding);
};

template <>
struct Operands<OperandLayout::_> {
	Operands(/*[[maybe_unused]]*/ uint32_t encoding) {
	}

	friend std::ostream &operator<<(std::ostream &output, /*[[maybe_unused]]*/ Operands &operands) {
		return output;
	}
};

template <>
struct Operands<OperandLayout::REG_IMM> {
	Register rA;
	int16_t imm;

	Operands(uint32_t encoding) : rA(static_cast<Register>(encoding >> 8 & 0xff)), imm(encoding >> 16 & 0xffff) {
		if (Register::_count <= rA) {
			throw std::invalid_argument("Invalid operands");
		}
	}

	friend std::ostream &operator<<(std::ostream &output, Operands &operands) {
		return output << " " << register_names[operands.rA] << " " << operands.imm;
	}
};

template <>
struct Operands<OperandLayout::REG_REG> {
	Register rA;
	Register rB;

	Operands(uint32_t encoding) : rA(static_cast<Register>(encoding >> 8 & 0xff)), rB(static_cast<Register>(encoding >> 16 & 0xff)) {
		if (Register::_count <= rA || Register::_count <= rB) {
			throw std::invalid_argument("Invalid operands");
		}
	}

	friend std::ostream &operator<<(std::ostream &output, Operands &operands) {
		return output << " " << register_names[operands.rA] << " " << register_names[operands.rB];
	}
};

template <>
struct Operands<OperandLayout::REG_REG_REG> {
	Register rA;
	Register rB;
	Register rC;

	explicit Operands(uint32_t encoding) : rA(static_cast<Register>(encoding >> 8 & 0xff)), rB(static_cast<Register>(encoding >> 16 & 0xff)), rC(static_cast<Register>(encoding >> 24 & 0xff)) {
		if (Register::_count <= rA || Register::_count <= rB || Register::_count <= rC) {
			throw std::invalid_argument("Invalid operands");
		}
	}

	friend std::ostream &operator<<(std::ostream &output, Operands &operands) {
		return output << " " << register_names[operands.rA] << " " << register_names[operands.rB] << " " << register_names[operands.rC];
	}
};

template <Opcode _Opcode, typename _Operands>
class Instruction {
  public:
	static const regular::Opcode Opcode = _Opcode;
	using Operands = _Operands;

	Operands operands;

  private:
	explicit Instruction(uint32_t encoding) : operands(encoding) {
	}
	template <size_t N>
	friend InstructionTypes createInstruction(uint32_t encoding);

	friend std::ostream &operator<<(std::ostream &output, Instruction &instruction) {
		return output << opcode_names[_Opcode] << instruction.operands;
	}
};

template <size_t N = 0>
InstructionTypes createInstruction(uint32_t encoding) {
	if ((encoding & 0xff) == N) {
		return InstructionTypes(decltype(std::get<N>(std::declval<InstructionTypes>())){encoding});
	} else if constexpr (N + 1 < std::variant_size_v<InstructionTypes>) {
		return createInstruction<N + 1>(encoding);
	} else {
		throw std::invalid_argument("Invalid opcode");
	}
}

} // namespace regular
