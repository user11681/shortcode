package user11681.shortcode.debug;

import it.unimi.dsi.fastutil.objects.ObjectArrayList;
import it.unimi.dsi.fastutil.objects.Reference2IntOpenHashMap;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import org.apache.logging.log4j.Logger;
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

    static void logInstructions(final MethodNode method) {
        logInstructions(method.instructions.iterator(), DEFAULT_OPTIONS);
    }

    static void logInstructions(final MethodNode method, final DebugOptions options) {
        logInstructions(method.instructions.iterator(), options);
    }

    static void logInstructions(final InsnList instructions) {
        logInstructions(instructions.iterator(), DEFAULT_OPTIONS);
    }

    static void logInstructions(final InsnList instructions, final DebugOptions options) {
        logInstructions(instructions.iterator(), options);
    }

    static void logInstructions(final Iterator<AbstractInsnNode> instructions) {
        logInstructions(instructions, DEFAULT_OPTIONS);
    }

    static void logInstructions(final Iterator<AbstractInsnNode> instructions, DebugOptions options) {
        final ObjectArrayList<String> lines = toString(instructions, options);
        final String[] lineArray = lines.elements();
        final int lineCount = lines.size();
        final Logger logger = options.logger;

        for (int i = 0; i < lineCount; i++) {
            logger.info(lineArray[i]);
        }
    }

    static ObjectArrayList<String> toString(final MethodNode method) {
        return toString(method.instructions.iterator(), DEFAULT_OPTIONS);
    }

    static ObjectArrayList<String> toString(final MethodNode method, final DebugOptions options) {
        return toString(method.instructions.iterator(), options);
    }

    static ObjectArrayList<String> toString(final InsnList instructions) {
        return toString(instructions.iterator(), DEFAULT_OPTIONS);
    }

    static ObjectArrayList<String> toString(final InsnList instructions, final DebugOptions options) {
        return toString(instructions.iterator(), options);
    }

    static ObjectArrayList<String> toString(final Iterator<AbstractInsnNode> instructions) {
        return toString(instructions, DEFAULT_OPTIONS);
    }

    static ObjectArrayList<String> toString(Iterator<AbstractInsnNode> instructions, final DebugOptions options) {
        final ObjectArrayList<String> lines = ObjectArrayList.wrap(new String[20], 0);
        final Reference2IntOpenHashMap<AbstractInsnNode> labelToIndex = new Reference2IntOpenHashMap<>();
        String[] lineArray;
        int labelIndex = 0;
        int size = 0;
        int index = 0;

        while (instructions.hasNext()) {
            lineArray = nodeToString(instructions.next(), labelToIndex, options).split("\n");

            if (options.indexes) {
                lineArray[0] = index++ + ":" + options.indentation + lineArray[0];
            }

            lines.addElements(size, lineArray);
            size += lineArray.length;
        }

        return lines;
    }

    static String nodeToString(final AbstractInsnNode instruction, final Map<AbstractInsnNode, Integer> labelToIndex) {
        return nodeToString(instruction, labelToIndex, DEFAULT_OPTIONS);
    }

    static String nodeToString(final AbstractInsnNode instruction, final Map<AbstractInsnNode, Integer> labelToIndex, final DebugOptions options) {
        final Function<? super AbstractInsnNode, ? extends Integer> labelToIndexMapper = (final AbstractInsnNode irrelevant) -> labelToIndex.size();
        final int opcode = instruction.getOpcode();
        final String string = opcode >= 0
            ? options.uppercase
            ? Shortcode.TO_STRING[opcode].toUpperCase()
            : Shortcode.TO_STRING[opcode]
            : null;

        switch (instruction.getType()) {
            case AbstractInsnNode.INSN:
                return options.indentation + string;
            case AbstractInsnNode.INT_INSN:
                final IntInsnNode intInstruction = (IntInsnNode) instruction;

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
                            return options.indentation + string + " " + Shortcode.ARRAY_TYPE_TO_STRING[intInstruction.operand];
                    }
                }

                return options.indentation + string + " " + intInstruction.operand;
            case AbstractInsnNode.VAR_INSN:
                return options.indentation + string + " " + ((VarInsnNode) instruction).var;
            case AbstractInsnNode.TYPE_INSN:
                return options.indentation + string + " " + ((TypeInsnNode) instruction).desc;
            case AbstractInsnNode.FIELD_INSN:
                final FieldInsnNode fieldInstruction = (FieldInsnNode) instruction;

                return options.indentation + "getstatic " + fieldInstruction.owner + "." + fieldInstruction.name + " : " + fieldInstruction.desc;
            case AbstractInsnNode.METHOD_INSN:
                final MethodInsnNode methodInstruction = (MethodInsnNode) instruction;

                return options.indentation + string + " " + methodInstruction.owner + "." + methodInstruction.name + methodInstruction.desc;
            case AbstractInsnNode.INVOKE_DYNAMIC_INSN:
                final InvokeDynamicInsnNode invokeDynamicInstruction = (InvokeDynamicInsnNode) instruction;

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
                final Object constant = ((LdcInsnNode) instruction).cst;

                return constant instanceof String
                    ? (options.indentation + string + " " + "\"" + constant + "\"")
                    : (options.indentation + string + " " + constant);
            case AbstractInsnNode.IINC_INSN:
                final IincInsnNode iIncInstruction = (IincInsnNode) instruction;

                return options.indentation + string + " " + iIncInstruction.var + " " + iIncInstruction.incr;
            case AbstractInsnNode.TABLESWITCH_INSN: {
                final TableSwitchInsnNode tableSwitchInstruction = (TableSwitchInsnNode) instruction;
                final StringBuilder switchBuilder = new StringBuilder();

                switchBuilder.append(options.indentation).append(string);

                final List<LabelNode> labels = tableSwitchInstruction.labels;
                final int max = tableSwitchInstruction.max;

                for (int index = tableSwitchInstruction.min; index < max; index++) {
                    switchBuilder.append(options.indentation).append(index).append(": L").append(labelToIndex.computeIfAbsent(labels.get(index), labelToIndexMapper));
                }

                switchBuilder.append(options.indentation).append("default: L").append(labelToIndex.computeIfAbsent(tableSwitchInstruction.dflt, labelToIndexMapper));

                return switchBuilder.toString();
            }
            case AbstractInsnNode.LOOKUPSWITCH_INSN: {
                final LookupSwitchInsnNode lookupSwitchInstruction = (LookupSwitchInsnNode) instruction;
                final StringBuilder switchBuilder = new StringBuilder();

                switchBuilder.append(options.indentation).append(string);

                final List<LabelNode> labels = lookupSwitchInstruction.labels;
                final List<Integer> keys = lookupSwitchInstruction.keys;
                final int keyCount = keys.size();

                for (int index = 0; index < keyCount; index++) {
                    switchBuilder.append(options.indentation).append(keys.get(index)).append(": L").append(labelToIndex.computeIfAbsent(labels.get(index), labelToIndexMapper));
                }

                switchBuilder.append(options.indentation).append("default: L").append(labelToIndex.computeIfAbsent(lookupSwitchInstruction.dflt, labelToIndexMapper));

                return switchBuilder.toString();
            }
            case AbstractInsnNode.MULTIANEWARRAY_INSN:
                final MultiANewArrayInsnNode multiANewArrayInstruction = (MultiANewArrayInsnNode) instruction;

                return options.indentation + string + multiANewArrayInstruction.desc + multiANewArrayInstruction.dims;
            case AbstractInsnNode.FRAME:
                final FrameNode frame = (FrameNode) instruction;
                final String type = options.uppercase ? Shortcode.FRAME_TYPE_TO_STRING.get(frame.type).toUpperCase() : Shortcode.FRAME_TYPE_TO_STRING.get(frame.type);

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

    static String stackToString(final List<Object> stack) {
        final StringBuilder builder = new StringBuilder("[");
        final int elementCount = stack.size();

        for (int i = 0; i < elementCount; i++) {
            builder.append(frameElementToString(stack.get(i)));

            if (i != elementCount - 1) {
                builder.append(' ');
            }
        }

        builder.append(']');

        return builder.toString();
    }

    static String frameElementToString(final Object element) {
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
