package user11681.shortcode.debug;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.FrameNode;
import org.objectweb.asm.tree.IincInsnNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.LineNumberNode;
import org.objectweb.asm.tree.LookupSwitchInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.MultiANewArrayInsnNode;
import org.objectweb.asm.tree.TableSwitchInsnNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.VarInsnNode;
import user11681.shortcode.Shortcode;

@SuppressWarnings({"unused", "RedundantSuppression"})
public interface Debug extends Opcodes {
    DebugOptions DEFAULT_OPTIONS = DebugOptions.defaultOptions();

    static void logInstructions(MethodNode method) {
        logInstructions(method.instructions.iterator(), DEFAULT_OPTIONS);
    }

    static void logInstructions(MethodNode method, DebugOptions options) {
        logInstructions(method.instructions.iterator(), options);
    }

    static void logInstructions(InsnList instructions) {
        logInstructions(instructions.iterator(), DEFAULT_OPTIONS);
    }

    static void logInstructions(InsnList instructions, DebugOptions options) {
        logInstructions(instructions.iterator(), options);
    }

    static void logInstructions(Iterator<AbstractInsnNode> instructions) {
        logInstructions(instructions, DEFAULT_OPTIONS);
    }

    static void logInstructions(Iterator<AbstractInsnNode> instructions, DebugOptions options) {

        toString(instructions, options).forEach(options.printer::print);
    }

    static List<String> toString(MethodNode method) {
        return toString(method.instructions.iterator(), DEFAULT_OPTIONS);
    }

    static List<String> toString(MethodNode method, DebugOptions options) {
        return toString(method.instructions.iterator(), options);
    }

    static List<String> toString(InsnList instructions) {
        return toString(instructions.iterator(), DEFAULT_OPTIONS);
    }

    static List<String> toString(InsnList instructions, DebugOptions options) {
        return toString(instructions.iterator(), options);
    }

    static List<String> toString(Iterator<AbstractInsnNode> instructions) {
        return toString(instructions, DEFAULT_OPTIONS);
    }

    static List<String> toString(Iterator<AbstractInsnNode> instructions, DebugOptions options) {
        List<String> lines = new ArrayList<>();
        Map<AbstractInsnNode, Integer> labelToIndex = new IdentityHashMap<>();
        String[] lineArray;
        int index = 0;

        while (instructions.hasNext()) {
            lineArray = nodeToString(instructions.next(), labelToIndex, options).split("\n");

            if (options.indexes) {
                lineArray[0] = index++ + ":" + options.indentation + lineArray[0];
            }

            Collections.addAll(lines, lineArray);
        }

        return lines;
    }

    static String nodeToString(AbstractInsnNode instruction, Map<AbstractInsnNode, Integer> labelToIndex) {
        return nodeToString(instruction, labelToIndex, DEFAULT_OPTIONS);
    }

    static String nodeToString(AbstractInsnNode instruction, Map<AbstractInsnNode, Integer> labelToIndex, DebugOptions options) {
        Function<? super AbstractInsnNode, ? extends Integer> labelToIndexMapper = (AbstractInsnNode irrelevant) -> labelToIndex.size();
        int opcode = instruction.getOpcode();
        String string = opcode >= 0
            ? options.uppercase
            ? Shortcode.toString[opcode].toUpperCase()
            : Shortcode.toString[opcode]
            : null;

        switch (instruction.getType()) {
            case AbstractInsnNode.INSN:
                return options.indentation + string;
            case AbstractInsnNode.INT_INSN:
                IntInsnNode intInstruction = (IntInsnNode) instruction;

                if (intInstruction.getOpcode() == NEWARRAY) {
                    switch (intInstruction.operand) {
                        case T_BOOLEAN:
                        case T_CHAR:
                        case T_FLOAT:
                        case T_DOUBLE:
                        case T_BYTE:
                        case T_SHORT:
                        case T_INT:
                        case T_LONG:
                            return options.indentation + string + " " + Shortcode.arrayTypeToString[intInstruction.operand];
                    }
                }

                return options.indentation + string + " " + intInstruction.operand;
            case AbstractInsnNode.VAR_INSN:
                return options.indentation + string + " " + ((VarInsnNode) instruction).var;
            case AbstractInsnNode.TYPE_INSN:
                return options.indentation + string + " " + ((TypeInsnNode) instruction).desc;
            case AbstractInsnNode.FIELD_INSN:
                FieldInsnNode fieldInstruction = (FieldInsnNode) instruction;

                return options.indentation + "getstatic " + fieldInstruction.owner + "." + fieldInstruction.name + " : " + fieldInstruction.desc;
            case AbstractInsnNode.METHOD_INSN:
                MethodInsnNode methodInstruction = (MethodInsnNode) instruction;

                return options.indentation + string + " " + methodInstruction.owner + "." + methodInstruction.name + methodInstruction.desc;
            case AbstractInsnNode.INVOKE_DYNAMIC_INSN:
                InvokeDynamicInsnNode invokeDynamicInstruction = (InvokeDynamicInsnNode) instruction;

                return
                    options.indentation + "invokedynamic " + invokeDynamicInstruction.name + invokeDynamicInstruction.desc + " [" +
                    options.indentation + options.indentation + invokeDynamicInstruction.bsm +
                    options.indentation + options.indentation + Arrays.toString(invokeDynamicInstruction.bsmArgs) +
                    "]";
            case AbstractInsnNode.JUMP_INSN:
                return options.indentation + string + " L" + labelToIndex.computeIfAbsent(((JumpInsnNode) instruction).label, labelToIndexMapper);
            case AbstractInsnNode.LABEL:
                return "L" + labelToIndex.computeIfAbsent(instruction, labelToIndexMapper);
            case AbstractInsnNode.LDC_INSN:
                Object constant = ((LdcInsnNode) instruction).cst;

                return constant instanceof String
                    ? (options.indentation + string + " " + "\"" + constant + "\"")
                    : (options.indentation + string + " " + constant);
            case AbstractInsnNode.IINC_INSN:
                IincInsnNode iIncInstruction = (IincInsnNode) instruction;

                return options.indentation + string + " " + iIncInstruction.var + " " + iIncInstruction.incr;
            case AbstractInsnNode.TABLESWITCH_INSN: {
                TableSwitchInsnNode tableSwitchInstruction = (TableSwitchInsnNode) instruction;
                StringBuilder switchBuilder = new StringBuilder();

                switchBuilder.append(options.indentation).append(string);

                List<LabelNode> labels = tableSwitchInstruction.labels;
                int max = tableSwitchInstruction.max;

                for (int index = tableSwitchInstruction.min; index < max; index++) {
                    switchBuilder.append(options.indentation).append(index).append(": L").append(labelToIndex.computeIfAbsent(labels.get(index), labelToIndexMapper));
                }

                switchBuilder.append(options.indentation).append("default: L").append(labelToIndex.computeIfAbsent(tableSwitchInstruction.dflt, labelToIndexMapper));

                return switchBuilder.toString();
            }
            case AbstractInsnNode.LOOKUPSWITCH_INSN: {
                LookupSwitchInsnNode lookupSwitchInstruction = (LookupSwitchInsnNode) instruction;
                StringBuilder switchBuilder = new StringBuilder();

                switchBuilder.append(options.indentation).append(string);

                List<LabelNode> labels = lookupSwitchInstruction.labels;
                List<Integer> keys = lookupSwitchInstruction.keys;
                int keyCount = keys.size();

                for (int index = 0; index < keyCount; index++) {
                    switchBuilder.append(options.indentation).append(keys.get(index)).append(": L").append(labelToIndex.computeIfAbsent(labels.get(index), labelToIndexMapper));
                }

                switchBuilder.append(options.indentation).append("default: L").append(labelToIndex.computeIfAbsent(lookupSwitchInstruction.dflt, labelToIndexMapper));

                return switchBuilder.toString();
            }
            case AbstractInsnNode.MULTIANEWARRAY_INSN:
                MultiANewArrayInsnNode multiANewArrayInstruction = (MultiANewArrayInsnNode) instruction;

                return options.indentation + string + multiANewArrayInstruction.desc + multiANewArrayInstruction.dims;
            case AbstractInsnNode.FRAME:
                FrameNode frame = (FrameNode) instruction;
                String type = options.uppercase ? Shortcode.frameToString.get(frame.type).toUpperCase() : Shortcode.frameToString.get(frame.type);

                switch (frame.type) {
                    case F_NEW:
                    case F_FULL:
                        return ("frame " + type + " " + stackToString(frame.local) + " " + stackToString(frame.stack));
                    case F_APPEND:
                        return ("frame " + type + " " + stackToString(frame.local));
                    case F_CHOP:
                        return ("frame " + type + " " + frame.local.size());
                    case F_SAME:
                        return ("frame " + type);
                    case F_SAME1:
                        return ("frame " + type + " " + frameElementToString(frame.stack.get(0)));
                }

                break;
            case AbstractInsnNode.LINE:
                return options.indentation + "line " + ((LineNumberNode) instruction).line + " L" + labelToIndex.computeIfAbsent(((LineNumberNode) instruction).start, labelToIndexMapper);
        }

        return "UNKNOWN";
    }

    static String stackToString(List<Object> stack) {
        StringBuilder builder = new StringBuilder("[");
        int elementCount = stack.size();

        for (int i = 0; i < elementCount; i++) {
            builder.append(frameElementToString(stack.get(i)));

            if (i != elementCount - 1) {
                builder.append(' ');
            }
        }

        builder.append(']');

        return builder.toString();
    }

    static String frameElementToString(Object element) {
        if (element instanceof Integer) {
            if (element == TOP) {
                return "top";
            } else if (element == INTEGER) {
                return "I";
            } else if (element == LONG) {
                return "J";
            } else if (element == FLOAT) {
                return "F";
            } else if (element == DOUBLE) {
                return "D";
            } else if (element == NULL) {
                return "null";
            } else if (element == UNINITIALIZED_THIS) {
                return "uninitialized_this";
            }
        }

        return element.toString();
    }
}
