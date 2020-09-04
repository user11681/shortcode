package user11681.shortcode;

import it.unimi.dsi.fastutil.objects.ReferenceArrayList;
import java.io.IOException;
import java.lang.annotation.Annotation;
import java.util.List;
import java.util.function.Predicate;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.FrameNode;
import org.objectweb.asm.tree.IincInsnNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.LineNumberNode;
import org.objectweb.asm.tree.LocalVariableNode;
import org.objectweb.asm.tree.LookupSwitchInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.MultiANewArrayInsnNode;
import org.objectweb.asm.tree.TableSwitchInsnNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.VarInsnNode;

public interface Shortcode extends Opcodes {
    int ABSTRACT_ALL = ACC_NATIVE | ACC_ABSTRACT;
    int INAPPLICABLE = 0;

    int[] DELTA_STACK_SIZE = {
        0,
        1,
        1,
        1,
        1,
        1,
        1,
        1,
        1,
        2,
        2,
        1,
        1,
        1,
        2,
        2,
        1,
        1,
        1,
        INAPPLICABLE,
        INAPPLICABLE,
        1,
        2,
        1,
        2,
        1,
        INAPPLICABLE,
        INAPPLICABLE,
        INAPPLICABLE,
        INAPPLICABLE,
        INAPPLICABLE,
        INAPPLICABLE,
        INAPPLICABLE,
        INAPPLICABLE,
        INAPPLICABLE,
        INAPPLICABLE,
        INAPPLICABLE,
        INAPPLICABLE,
        INAPPLICABLE,
        INAPPLICABLE,
        INAPPLICABLE,
        INAPPLICABLE,
        INAPPLICABLE,
        INAPPLICABLE,
        INAPPLICABLE,
        INAPPLICABLE,
        -1,
        0,
        -1,
        0,
        -1,
        -1,
        -1,
        -1,
        -1,
        -2,
        -1,
        -2,
        -1,
        INAPPLICABLE,
        INAPPLICABLE,
        INAPPLICABLE,
        INAPPLICABLE,
        INAPPLICABLE,
        INAPPLICABLE,
        INAPPLICABLE,
        INAPPLICABLE,
        INAPPLICABLE,
        INAPPLICABLE,
        INAPPLICABLE,
        INAPPLICABLE,
        INAPPLICABLE,
        INAPPLICABLE,
        INAPPLICABLE,
        INAPPLICABLE,
        INAPPLICABLE,
        INAPPLICABLE,
        INAPPLICABLE,
        INAPPLICABLE,
        -3,
        -4,
        -3,
        -4,
        -3,
        -3,
        -3,
        -3,
        -1,
        -2,
        1,
        1,
        1,
        2,
        2,
        2,
        0,
        -1,
        -2,
        -1,
        -2,
        -1,
        -2,
        -1,
        -2,
        -1,
        -2,
        -1,
        -2,
        -1,
        -2,
        -1,
        -2,
        -1,
        -2,
        -1,
        -2,
        0,
        0,
        0,
        0,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -2,
        -1,
        -2,
        -1,
        -2,
        0,
        1,
        0,
        1,
        -1,
        -1,
        0,
        0,
        1,
        1,
        -1,
        0,
        -1,
        0,
        0,
        0,
        -3,
        -1,
        -1,
        -3,
        -3,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -2,
        -2,
        -2,
        -2,
        -2,
        -2,
        -2,
        -2,
        0,
        1,
        0,
        -1,
        -1,
        -1,
        -2,
        -1,
        -2,
        -1,
        0,
        INAPPLICABLE,
        INAPPLICABLE,
        INAPPLICABLE,
        INAPPLICABLE,
        INAPPLICABLE,
        INAPPLICABLE,
        INAPPLICABLE,
        INAPPLICABLE,
        INAPPLICABLE,
        1,
        0,
        0,
        0,
        INAPPLICABLE,
        0,
        0,
        -1,
        -1,
        INAPPLICABLE,
        INAPPLICABLE,
        -1,
        -1,
        INAPPLICABLE,
        INAPPLICABLE
    };

    String[] TO_STRING = {
        "nop",
        "aconst_null",
        "iconst_m1",
        "iconst_0",
        "iconst_1",
        "iconst_2",
        "iconst_3",
        "iconst_4",
        "iconst_5",
        "lconst_0",
        "lconst_1",
        "fconst_0",
        "fconst_1",
        "fconst_2",
        "dconst_0",
        "dconst_1",
        "bipush",
        "sipush",
        "ldc",
        "iload",
        "lload",
        "fload",
        "dload",
        "aload",
        "iaload",
        "laload",
        "faload",
        "daload",
        "aaload",
        "baload",
        "caload",
        "saload",
        "istore",
        "lstore",
        "fstore",
        "dstore",
        "astore",
        "iastore",
        "lastore",
        "fastore",
        "dastore",
        "aastore",
        "bastore",
        "castore",
        "sastore",
        "pop",
        "pop2",
        "dup",
        "dup_x1",
        "dup_x2",
        "dup2",
        "dup2_x1",
        "dup2_x2",
        "swap",
        "iadd",
        "ladd",
        "fadd",
        "dadd",
        "isub",
        "lsub",
        "fsub",
        "dsub",
        "imul",
        "lmul",
        "fmul",
        "dmul",
        "idiv",
        "ldiv",
        "fdiv",
        "ddiv",
        "irem",
        "lrem",
        "frem",
        "drem",
        "ineg",
        "lneg",
        "fneg",
        "dneg",
        "ishl",
        "lshl",
        "ishr",
        "lshr",
        "iushr",
        "lushr",
        "iand",
        "land",
        "ior",
        "lor",
        "ixor",
        "lxor",
        "iinc",
        "i2l",
        "i2f",
        "i2d",
        "l2i",
        "l2f",
        "l2d",
        "f2i",
        "f2l",
        "f2d",
        "d2i",
        "d2l",
        "d2f",
        "i2b",
        "i2c",
        "i2s",
        "lcmp",
        "fcmpl",
        "fcmpg",
        "dcmpl",
        "dcmpg",
        "ifeq",
        "ifne",
        "iflt",
        "ifge",
        "ifgt",
        "ifle",
        "if_icmpeq",
        "if_icmpne",
        "if_icmplt",
        "if_icmpge",
        "if_icmpgt",
        "if_icmple",
        "if_acmpeq",
        "if_acmpne",
        "goto",
        "jsr",
        "ret",
        "tableswitch",
        "lookupswitch",
        "ireturn",
        "lreturn",
        "freturn",
        "dreturn",
        "areturn",
        "return",
        "getstatic",
        "putstatic",
        "getfield",
        "putfield",
        "invokevirtual",
        "invokespecial",
        "invokestatic",
        "invokeinterface",
        "invokedynamic",
        "new",
        "newarray",
        "anewarray",
        "arraylength",
        "athrow",
        "checkcast",
        "instanceof",
        "monitorenter",
        "monitorexit",
        "multianewarray",
        "ifnull",
        "ifnonnull"
    };

    static String getInternalName(final Class<?> klass) {
        return toInternalName(klass.getName());
    }

    static String toInternalName(final String binaryName) {
        return binaryName.replace('.', '/');
    }

    static String getBinaryName(final ClassNode klass) {
        return toBinaryName(klass.name);
    }

    static String toBinaryName(final String internalName) {
        return internalName.replace('/', '.');
    }

    static String toDescriptor(final String name) {
        return "L" + toInternalName(name) + ";";
    }

    static void insertBeforeEveryReturn(final MethodNode in, final AbstractInsnNode instruction) {
        final InsnList box = new InsnList();

        box.add(instruction);
    }

    static void insertBeforeEveryReturn(final MethodNode in, final InsnList instructions) {
        final LabelNode end = new LabelNode();
        final int locals = in.maxLocals;
        AbstractInsnNode instruction = instructions.getFirst();
        int opcode;

        while (instruction != null) {
            opcode = instruction.getOpcode();

            if (Shortcode.isLoadOpcode(opcode) || Shortcode.isStoreOpcode(opcode)) {
                ((VarInsnNode) instruction).var += locals;
            }

            if (Shortcode.isReturnInstruction(instruction)) {
                instructions.set(instruction, new JumpInsnNode(Opcodes.GOTO, end));
            }

            instruction = instruction.getNext();
        }

        instructions.add(end);

        instruction = in.instructions.getFirst();

        while (instruction != null) {
            if (Shortcode.isReturnInstruction(instruction)) {
                in.instructions.insertBefore(instruction, Shortcode.copyInstructions(instructions));
            }

            instruction = instruction.getNext();
        }
    }

    static MethodNode copyMethod(final ClassNode klass, final MethodNode method) {
        method.accept(klass);

        return Shortcode.getFirstMethod(klass, method.name);
    }

    static InsnList copyInstructions(final InsnList instructions) {
        return copyInstructions(instructions, new InsnList());
    }

    static <T extends InsnList> T copyInstructions(final InsnList instructions, final T storage) {
        AbstractInsnNode instruction = instructions.getFirst();

        while (instruction != null) {
            storage.add(copyInstruction(instruction));

            instruction = instruction.getNext();
        }

        return storage;
    }

    static <T extends AbstractInsnNode> T copyInstruction(final T instruction) {
        if (instruction instanceof InsnNode) {
            return (T) new InsnNode(instruction.getOpcode());
        } else if (instruction instanceof VarInsnNode) {
            return (T) new VarInsnNode(instruction.getOpcode(), ((VarInsnNode) instruction).var);
        } else if (instruction instanceof FieldInsnNode) {
            final FieldInsnNode fieldInstruction = (FieldInsnNode) instruction;

            return (T) new FieldInsnNode(instruction.getOpcode(), fieldInstruction.owner, fieldInstruction.name, fieldInstruction.desc);
        } else if (instruction instanceof MethodInsnNode) {
            final MethodInsnNode methodInstruction = (MethodInsnNode) instruction;

            return (T) new MethodInsnNode(instruction.getOpcode(), methodInstruction.owner, methodInstruction.name, methodInstruction.desc, methodInstruction.itf);
        } else if (instruction instanceof InvokeDynamicInsnNode) {
            final InvokeDynamicInsnNode lambdaInstruction = (InvokeDynamicInsnNode) instruction;

            return (T) new InvokeDynamicInsnNode(lambdaInstruction.name, lambdaInstruction.desc, lambdaInstruction.bsm, lambdaInstruction.bsmArgs);
        } else if (instruction instanceof TypeInsnNode) {
            return (T) new TypeInsnNode(instruction.getOpcode(), ((TypeInsnNode) instruction).desc);
        } else if (instruction instanceof MultiANewArrayInsnNode) {
            final MultiANewArrayInsnNode arrayInstruction = (MultiANewArrayInsnNode) instruction;

            return (T) new MultiANewArrayInsnNode(arrayInstruction.desc, arrayInstruction.dims);
        } else if (instruction instanceof LabelNode) {
            return (T) new LabelNode(((LabelNode) instruction).getLabel());
        } else if (instruction instanceof IntInsnNode) {
            return (T) new IntInsnNode(instruction.getOpcode(), ((IntInsnNode) instruction).operand);
        } else if (instruction instanceof LdcInsnNode) {
            return (T) new LdcInsnNode(((LdcInsnNode) instruction).cst);
        } else if (instruction instanceof FrameNode) {
            final FrameNode frameNode = (FrameNode) instruction;

            return (T) new FrameNode(frameNode.getOpcode(), frameNode.local.size(), frameNode.local.toArray(), frameNode.stack.size(), frameNode.stack.toArray());
        } else if (instruction instanceof JumpInsnNode) {
            return (T) new JumpInsnNode(instruction.getOpcode(), ((JumpInsnNode) instruction).label);
        } else if (instruction instanceof IincInsnNode) {
            final IincInsnNode incrementation = (IincInsnNode) instruction;

            return (T) new IincInsnNode(incrementation.var, incrementation.incr);
        } else if (instruction instanceof LineNumberNode) {
            final LineNumberNode lineNode = (LineNumberNode) instruction;

            return (T) new LineNumberNode(lineNode.line, lineNode.start);
        } else if (instruction instanceof LookupSwitchInsnNode) {
            final LookupSwitchInsnNode lookupSwitchNode = (LookupSwitchInsnNode) instruction;
            final Object[] keyObjects = lookupSwitchNode.keys.toArray();
            final int[] keys = new int[keyObjects.length];

            for (int i = 0; i < keyObjects.length; i++) {
                keys[i] = (int) keyObjects[i];
            }

            return (T) new LookupSwitchInsnNode(lookupSwitchNode.dflt, keys, lookupSwitchNode.labels.toArray(new LabelNode[0]));
        } else if (instruction instanceof TableSwitchInsnNode) {
            final TableSwitchInsnNode tableSwitchNode = (TableSwitchInsnNode) instruction;

            return (T) new TableSwitchInsnNode(tableSwitchNode.min, tableSwitchNode.max, tableSwitchNode.dflt, tableSwitchNode.labels.toArray(new LabelNode[0]));
        }

        throw new IllegalArgumentException(String.valueOf(instruction));
    }

    static ClassNode getClassNode(final Class<?> klass) {
        try {
            final ClassNode node = new ClassNode();
            final ClassReader reader = new ClassReader(klass.getName());

            reader.accept(node, 0);

            return node;
        } catch (IOException exception) {
            throw new RuntimeException(exception);
        }
    }

    static ClassNode getClassNode(final String className) {
        try {
            final ClassNode klass = new ClassNode();
            final ClassReader reader = new ClassReader(className);

            reader.accept(klass, 0);

            return klass;
        } catch (IOException exception) {
            throw new RuntimeException(exception);
        }
    }

    static LocalVariableNode getLocalVariable(final MethodNode method, final int index) {
        LocalVariableNode result = null;

        for (final LocalVariableNode local : method.localVariables) {
            if (index == local.index) {
                result = local;

                break;
            }
        }

        return result;
    }

    static LocalVariableNode getLocalVariable(final MethodNode method, final String name) {
        LocalVariableNode result = null;

        for (final LocalVariableNode local : method.localVariables) {
            if (name.equals(local.name)) {
                result = local;

                break;
            }
        }

        return result;
    }

    static ReferenceArrayList<AbstractInsnNode> getInstructions(final ClassNode klass, final String method) {
        return getInstructions(getFirstMethod(klass, method));
    }

    static ReferenceArrayList<AbstractInsnNode> getInstructions(final MethodNode method) {
        return new ReferenceArrayList<>(method.instructions.toArray());
    }

    static MethodNode getFirstInheritedMethod(ClassNode klass, final String name) {
        MethodNode first = null;

        outer:
        while (true) {
            for (final MethodNode method : klass.methods) {
                if (name.equals(method.name)) {
                    first = method;
                    break outer;
                }
            }

            if (klass.superName != null) {
                try {
                    final ClassReader reader = new ClassReader(klass.superName);

                    klass = new ClassNode();

                    reader.accept(klass, 0);
                } catch (final IOException exception) {
                    throw new RuntimeException(exception);
                }
            } else {
                break;
            }
        }

        return first;
    }

    static MethodNode getFirstMethod(final ClassNode klass, final String name) {
        MethodNode first = null;

        for (final MethodNode method : klass.methods) {
            if (name.equals(method.name)) {
                first = method;
                break;
            }
        }

        return first;
    }

    static ReferenceArrayList<MethodNode> getAllMethods(ClassNode klass) {
        final ReferenceArrayList<MethodNode> methods = new ReferenceArrayList<>();

        while (true) {
            methods.addAll(klass.methods);

            if (klass.superName != null) {
                try {
                    final ClassReader reader = new ClassReader(klass.superName);

                    klass = new ClassNode();

                    reader.accept(klass, 0);
                } catch (final IOException exception) {
                    throw new RuntimeException(exception);
                }
            } else {
                break;
            }
        }

        return methods;
    }

    static ReferenceArrayList<MethodNode> getMethods(final String internalClassName, final String name) {
        return getMethods(getClassNode(internalClassName), name);
    }

    static ReferenceArrayList<MethodNode> getMethods(final ClassNode klass, final String name) {
        final ReferenceArrayList<MethodNode> methods = new ReferenceArrayList<>();

        for (final MethodNode method : klass.methods) {
            if (name.equals(method.name)) {
                methods.add(method);
            }
        }

        return methods;
    }

    static ReferenceArrayList<AbstractInsnNode> getInstructions(final InsnList instructions, final Predicate<AbstractInsnNode> condition) {
        final ReferenceArrayList<AbstractInsnNode> matchingInstructions = new ReferenceArrayList<>();

        for (final AbstractInsnNode instruction : instructions) {
            if (condition.test(instruction)) {
                matchingInstructions.add(instruction);
            }
        }

        return matchingInstructions;
    }

    static int countExplicitParameters(final InvokeDynamicInsnNode instruction) {
        return countExplicitParameters(instruction.desc);
    }

    static int countExplicitParameters(final MethodInsnNode instruction) {
        return countExplicitParameters(instruction.desc);
    }

    static int countExplicitParameters(final MethodNode method) {
        return countExplicitParameters(method.desc);
    }

    static int countExplicitParameters(final String descriptor) {
        final String terminators = "VZCBSIJFD;";
        final int end = descriptor.indexOf(')');
        int parameterCount = 0;
        int length = 0;
        char character;

        for (int i = descriptor.indexOf('(') + 1; i < end; ++i) {
            character = descriptor.charAt(i);
            ++length;

            if (terminators.indexOf(character) >= 0 && (length == 1 || character == ';' || length == 2 && descriptor.charAt(i - 1) == '[')) {
                ++parameterCount;
                length = 0;
            }
        }

        return parameterCount;
    }

    static ReferenceArrayList<String> getExplicitParameters(final InvokeDynamicInsnNode instruction) {
        return getExplicitParameters(instruction.desc);
    }

    static ReferenceArrayList<String> getExplicitParameters(final MethodInsnNode instruction) {
        return getExplicitParameters(instruction.desc);
    }

    static ReferenceArrayList<String> getExplicitParameters(final MethodNode method) {
        return getExplicitParameters(method.desc);
    }

    static ReferenceArrayList<String> getExplicitParameters(final String descriptor) {
        final ReferenceArrayList<String> parameters = new ReferenceArrayList<>();
        final int end = descriptor.indexOf(')');
        final StringBuilder parameter = new StringBuilder();
        final String primitives = "VZCBSIJFD";
        char character;

        for (int i = descriptor.indexOf('(') + 1; i < end; ++i) {
            character = descriptor.charAt(i);
            parameter.append(character);

            if (character == ';' || primitives.indexOf(character) >= 0 && (parameter.length() == 1 || parameter.length() == 2 && parameter.charAt(0) == '[')) {
                parameters.add(parameter.toString());
                parameter.delete(0, parameter.length());
            }
        }

        return parameters;
    }

    static String getReturnType(final InvokeDynamicInsnNode instruction) {
        return getReturnType(instruction.desc);
    }

    static String getReturnType(final MethodInsnNode instruction) {
        return getReturnType(instruction.desc);
    }

    static String getReturnType(final MethodNode method) {
        return getReturnType(method.desc);
    }

    static String getReturnType(final String descriptor) {
        return descriptor.substring(descriptor.indexOf(')') + 1);
    }

    static ReferenceArrayList<String> parseDescriptor(final InvokeDynamicInsnNode instruction) {
        return parseDescriptor(instruction.desc);
    }

    static ReferenceArrayList<String> parseDescriptor(final MethodInsnNode instruction) {
        return parseDescriptor(instruction.desc);
    }

    static ReferenceArrayList<String> parseDescriptor(final MethodNode method) {
        return parseDescriptor(method.desc);
    }

    static ReferenceArrayList<String> parseDescriptor(final String descriptor) {
        final ReferenceArrayList<String> types = new ReferenceArrayList<>();
        final int end = descriptor.indexOf(')');
        final String primitives = "VZCBSIJFD";
        final StringBuilder parameter = new StringBuilder();
        char character;

        for (int i = descriptor.indexOf('(') + 1; i < end; ++i) {
            character = descriptor.charAt(i);

            parameter.append(character);

            if (character == ';' || primitives.indexOf(character) >= 0 && (parameter.length() == 1 || parameter.length() == 2 && parameter.charAt(0) == '[')) {
                types.add(parameter.toString());

                parameter.delete(0, parameter.length());
            }
        }

        types.add(descriptor.substring(descriptor.indexOf(')') + 1));

        return types;
    }

    static <T> T getAnnotationValue(final List<AnnotationNode> annotations, final Class<? extends Annotation> type, final String property, final T alternative) {
        return getAnnotationValue(annotations, Type.getDescriptor(type), property, alternative);
    }

    static <T> T getAnnotationValue(final List<AnnotationNode> annotations, final String annotationDescriptor, final String property, final T alternative) {
        final AnnotationNode[] annotationArray = annotations.toArray(new AnnotationNode[0]);
        Object[] values;

        for (int i = 0; i < annotationArray.length; i++) {
            if (annotationDescriptor.equals(annotationArray[i].desc)) {
                values = annotationArray[i].values.toArray();

                for (int j = 0; j < values.length; j++) {
                    if (property.equals(values[j])) {
                        //noinspection unchecked
                        return (T) values[j + i];
                    }
                }

                return alternative;
            }
        }

        return null;
    }

    static <T> T getAnnotationValue(final AnnotationNode annotation, final String property, final T alternative) {
        final Object[] values = annotation.values.toArray();
        final int size = values.length;

        for (int i = 0; i < size; i += 2) {
            if (property.equals(values[i])) {
                //noinspection unchecked
                return (T) values[i + 1];
            }
        }

        return alternative;
    }

    static <T> T getAnnotationValue(final AnnotationNode annotation, final String property) {
        final Object[] values = annotation.values.toArray();
        final int size = values.length;

        for (int i = 0; i < size; i += 2) {
            if (property.equals(values[i])) {
                //noinspection unchecked
                return (T) values[i + 1];
            }
        }

        throw new RuntimeException(String.format("cannot find the value of %s in %s", property, annotation));
    }

    static Object getDefaultValue(final String descriptor) {
        switch (descriptor) {
            case "Z":
                return false;
            case "C":
                return (char) 0;
            case "B":
                return (byte) 0;
            case "S":
                return (short) 0;
            case "I":
                return 0;
            case "J":
                return 0L;
            case "F":
                return 0F;
            case "D":
                return 0D;
            default:
                return null;
        }
    }

    static int getLoadOpcode(final String descriptor) {
        switch (descriptor) {
            case "Z":
            case "C":
            case "B":
            case "S":
            case "I":
                return ILOAD;
            case "J":
                return LLOAD;
            case "F":
                return FLOAD;
            case "D":
                return DLOAD;
            default:
                return ALOAD;
        }
    }

    static int getReturnOpcode(final MethodNode method) {
        return getReturnOpcode(getReturnType(method.desc));
    }

    static int getReturnOpcode(final String descriptor) {
        switch (descriptor) {
            case "Z":
            case "C":
            case "B":
            case "S":
            case "I":
                return IRETURN;
            case "J":
                return LRETURN;
            case "F":
                return FRETURN;
            case "D":
                return DRETURN;
            case "V":
                return RETURN;
            default:
                return ARETURN;
        }
    }

    static boolean isReturnInstruction(final AbstractInsnNode instruction) {
        return isReturnOpcode(instruction.getOpcode());
    }

    static boolean isReturnOpcode(final int opcode) {
        switch (opcode) {
            case IRETURN:
            case LRETURN:
            case FRETURN:
            case DRETURN:
            case ARETURN:
            case RETURN:
                return true;
            default:
                return false;
        }
    }

    static boolean isLoadOpcode(final int opcode) {
        switch (opcode) {
            case ILOAD:
            case LLOAD:
            case FLOAD:
            case DLOAD:
            case ALOAD:
                return true;
            default:
                return false;
        }
    }

    static boolean isStoreOpcode(final int opcode) {
        switch (opcode) {
            case ISTORE:
            case LSTORE:
            case FSTORE:
            case DSTORE:
            case ASTORE:
                return true;
            default:
                return false;
        }
    }
}
