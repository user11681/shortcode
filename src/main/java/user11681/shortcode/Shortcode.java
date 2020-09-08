package user11681.shortcode;

import it.unimi.dsi.fastutil.ints.Int2ReferenceOpenHashMap;
import it.unimi.dsi.fastutil.objects.ReferenceArrayList;
import java.io.IOException;
import java.lang.annotation.Annotation;
import java.lang.reflect.Array;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;
import java.util.Objects;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Predicate;
import org.objectweb.asm.AnnotationVisitor;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.TypePath;
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
import org.objectweb.asm.tree.LocalVariableAnnotationNode;
import org.objectweb.asm.tree.LocalVariableNode;
import org.objectweb.asm.tree.LookupSwitchInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.MultiANewArrayInsnNode;
import org.objectweb.asm.tree.TableSwitchInsnNode;
import org.objectweb.asm.tree.TypeAnnotationNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.VarInsnNode;

@SuppressWarnings({"unused", "RedundantSuppression", "unchecked"})
public interface Shortcode extends Opcodes {
    int ABSTRACT_ALL = ACC_NATIVE | ACC_ABSTRACT;
    int NA = 0;
    int ANNOTATION_VISITOR = 0;
    int ANNOTATION_NODE = 1;
    int TYPE_ANNOTATION_NODE = 2;
    int LOCAL_VARIABLE_ANNOTATION_NODE = 3;

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
        NA,
        NA,
        1,
        2,
        1,
        2,
        1,
        NA,
        NA,
        NA,
        NA,
        NA,
        NA,
        NA,
        NA,
        NA,
        NA,
        NA,
        NA,
        NA,
        NA,
        NA,
        NA,
        NA,
        NA,
        NA,
        NA,
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
        NA,
        NA,
        NA,
        NA,
        NA,
        NA,
        NA,
        NA,
        NA,
        NA,
        NA,
        NA,
        NA,
        NA,
        NA,
        NA,
        NA,
        NA,
        NA,
        NA,
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
        NA,
        NA,
        NA,
        NA,
        NA,
        NA,
        NA,
        NA,
        NA,
        1,
        0,
        0,
        0,
        NA,
        0,
        0,
        -1,
        -1,
        NA,
        NA,
        -1,
        -1,
        NA,
        NA
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
        "ldc_w",
        "ldc2_w",
        "iload",
        "lload",
        "fload",
        "dload",
        "aload",
        "iload_0",
        "iload_1",
        "iload_2",
        "iload_3",
        "lload_0",
        "lload_1",
        "lload_2",
        "lload_3",
        "fload_0",
        "fload_1",
        "fload_2",
        "fload_3",
        "dload_0",
        "dload_1",
        "dload_2",
        "dload_3",
        "aload_0",
        "aload_1",
        "aload_2",
        "aload_3",
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
        "istore_0",
        "istore_1",
        "istore_2",
        "istore_3",
        "lstore_0",
        "lstore_1",
        "lstore_2",
        "lstore_3",
        "fstore_0",
        "fstore_1",
        "fstore_2",
        "fstore_3",
        "dstore_0",
        "dstore_1",
        "dstore_2",
        "dstore_3",
        "astore_0",
        "astore_1",
        "astore_2",
        "astore_3",
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
        "wide",
        "multianewarray",
        "ifnull",
        "ifnonnulL"
    };

    String[] ARRAY_TYPE_TO_STRING = {
        "T_BOOLEAN",
        "T_CHAR",
        "T_FLOAT",
        "T_DOUBLE",
        "T_BYTE",
        "T_SHORT",
        "T_INT",
        "T_LONG",
    };

    Int2ReferenceOpenHashMap<String> FRAME_TYPE_TO_STRING = new Int2ReferenceOpenHashMap<>(
        new int[]{-1, 0, 1, 2, 3, 4},
        new String[]{"new", "full", "append", "chop", "same", "same1"},
        0.75F
    );

    ClassToIntMap CLASS_TO_INT = new ClassToIntMap(
        new Class[]{AnnotationVisitor.class, AnnotationNode.class, TypeAnnotationNode.class, LocalVariableAnnotationNode.class},
        new int[]{ANNOTATION_VISITOR, ANNOTATION_NODE, TYPE_ANNOTATION_NODE, LOCAL_VARIABLE_ANNOTATION_NODE}
    );

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

        return Shortcode.getFirstDeclaredMethod(klass, method.name);
    }

    static InsnList copyInstructions(final InsnList instructions) {
        return copyInstructions(instructions, new InsnList());
    }

    static <T extends InsnList> T copyInstructions(final InsnList instructions, final T storage) {
        AbstractInsnNode instruction = instructions.getFirst();

        while (instruction != null) {
            storage.add(clone(instruction));

            instruction = instruction.getNext();
        }

        return storage;
    }

    static List<? extends AbstractInsnNode> clone(final List<? extends AbstractInsnNode> instructions) {
        final int length = instructions.size();
        final ReferenceArrayList<AbstractInsnNode> clones = new ReferenceArrayList<>(length);

        for (int i = 0; i < length; i++) {
            clones.add(clone(instructions.get(i)));
        }

        return clones;
    }

    static <T extends AbstractInsnNode> T[] clone(final T... instructions) {
        final int length = instructions.length;
        final T[] clones = (T[]) Array.newInstance(instructions.getClass().getComponentType(), length);

        for (int i = 0; i < length; i++) {
            clones[i] = clone(instructions[i]);
        }

        return clones;
    }

    static <T extends AbstractInsnNode> T clone(final T instruction) {
        switch (instruction.getType()) {
            case AbstractInsnNode.INSN:
                return (T) new InsnNode(instruction.getOpcode());
            case AbstractInsnNode.INT_INSN:
                return (T) new IntInsnNode(instruction.getOpcode(), ((IntInsnNode) instruction).operand);
            case AbstractInsnNode.VAR_INSN:
                return (T) new VarInsnNode(instruction.getOpcode(), ((VarInsnNode) instruction).var);
            case AbstractInsnNode.TYPE_INSN:
                return (T) new TypeInsnNode(instruction.getOpcode(), ((TypeInsnNode) instruction).desc);
            case AbstractInsnNode.FIELD_INSN:
                final FieldInsnNode fieldInstruction = (FieldInsnNode) instruction;

                return (T) new FieldInsnNode(instruction.getOpcode(), fieldInstruction.owner, fieldInstruction.name, fieldInstruction.desc);
            case AbstractInsnNode.METHOD_INSN:
                final MethodInsnNode methodInstruction = (MethodInsnNode) instruction;

                return (T) new MethodInsnNode(instruction.getOpcode(), methodInstruction.owner, methodInstruction.name, methodInstruction.desc, methodInstruction.itf);
            case AbstractInsnNode.INVOKE_DYNAMIC_INSN:
                final InvokeDynamicInsnNode lambdaInstruction = (InvokeDynamicInsnNode) instruction;
                final Object[] args = lambdaInstruction.bsmArgs;

                return (T) new InvokeDynamicInsnNode(lambdaInstruction.name, lambdaInstruction.desc, lambdaInstruction.bsm, Arrays.copyOf(args, args.length));
            case AbstractInsnNode.JUMP_INSN:
                return (T) new JumpInsnNode(instruction.getOpcode(), ((JumpInsnNode) instruction).label);
            case AbstractInsnNode.LABEL:
                return (T) new LabelNode(((LabelNode) instruction).getLabel());
            case AbstractInsnNode.LDC_INSN:
                return (T) new LdcInsnNode(((LdcInsnNode) instruction).cst);
            case AbstractInsnNode.IINC_INSN:
                final IincInsnNode incrementation = (IincInsnNode) instruction;

                return (T) new IincInsnNode(incrementation.var, incrementation.incr);
            case AbstractInsnNode.TABLESWITCH_INSN:
                final TableSwitchInsnNode tableSwitchNode = (TableSwitchInsnNode) instruction;

                return (T) new TableSwitchInsnNode(tableSwitchNode.min, tableSwitchNode.max, clone(tableSwitchNode.dflt), clone(tableSwitchNode.labels).toArray(new LabelNode[0]));
            case AbstractInsnNode.LOOKUPSWITCH_INSN:
                final LookupSwitchInsnNode lookupSwitchNode = (LookupSwitchInsnNode) instruction;
                final Object[] keyObjects = lookupSwitchNode.keys.toArray();
                final int[] keys = new int[keyObjects.length];

                for (int i = 0; i < keyObjects.length; i++) {
                    keys[i] = (int) keyObjects[i];
                }

                return (T) new LookupSwitchInsnNode(clone(lookupSwitchNode.dflt), keys, clone(lookupSwitchNode.labels).toArray(new LabelNode[0]));
            case AbstractInsnNode.MULTIANEWARRAY_INSN:
                final MultiANewArrayInsnNode arrayInstruction = (MultiANewArrayInsnNode) instruction;

                return (T) new MultiANewArrayInsnNode(arrayInstruction.desc, arrayInstruction.dims);
            case AbstractInsnNode.FRAME:
                final FrameNode frameNode = (FrameNode) instruction;

                return (T) new FrameNode(frameNode.getOpcode(), frameNode.local.size(), frameNode.local.toArray(), frameNode.stack.size(), frameNode.stack.toArray());
            case AbstractInsnNode.LINE:
                final LineNumberNode lineNode = (LineNumberNode) instruction;

                return (T) new LineNumberNode(lineNode.line, clone(lineNode.start));
        }

        throw new IllegalArgumentException(String.valueOf(instruction));
    }

    static ClassNode getClassNode(final Class<?> klass) {
        try {
            final ClassNode node = new ClassNode();
            final ClassReader reader = new ClassReader(klass.getName());

            reader.accept(node, 0);

            return node;
        } catch (final IOException exception) {
            throw new RuntimeException(exception);
        }
    }

    static ClassNode getClassNode(final String className) {
        try {
            final ClassNode klass = new ClassNode();
            final ClassReader reader = new ClassReader(className);

            reader.accept(klass, 0);

            return klass;
        } catch (final IOException exception) {
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
        return getInstructions(getFirstDeclaredMethod(klass, method));
    }

    static ReferenceArrayList<AbstractInsnNode> getInstructions(final MethodNode method) {
        return new ReferenceArrayList<>(method.instructions.toArray());
    }

    static MethodNode tryGetFirstMethod(ClassNode klass, final String name) {
        for (final MethodNode method : klass.methods) {
            if (name.equals(method.name)) {
                return method;
            }
        }

        if (klass.superName != null) {
            try {
                final ClassReader reader = new ClassReader(klass.superName);

                klass = new ClassNode();

                reader.accept(klass, 0);

                return tryGetFirstMethod(klass, name);
            } catch (final IOException exception) {
                throw new RuntimeException(exception);
            }
        }

        return null;
    }

    static MethodNode getFirstMethod(ClassNode klass, final String name) {
        for (final MethodNode method : klass.methods) {
            if (name.equals(method.name)) {
                return method;
            }
        }

        if (klass.superName != null) {
            try {
                final ClassReader reader = new ClassReader(klass.superName);

                klass = new ClassNode();

                reader.accept(klass, 0);

                return getFirstMethod(klass, name);
            } catch (final IOException exception) {
                throw new RuntimeException(exception);
            }
        }

        throw new IllegalArgumentException(String.format("the given ClassNode does not contain method %s", name));
    }

    static MethodNode tryGetFirstDeclaredMethod(final ClassNode klass, final String name) {
        for (final MethodNode method : klass.methods) {
            if (name.equals(method.name)) {
                return method;
            }
        }

        return null;
    }

    static MethodNode getFirstDeclaredMethod(final ClassNode klass, final String name) {
        for (final MethodNode method : klass.methods) {
            if (name.equals(method.name)) {
                return method;
            }
        }

        throw new IllegalArgumentException(String.format("the given ClassNode does not contain method %s", name));
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

    static void findBackward(final ListIterator<AbstractInsnNode> iterator, final Predicate<AbstractInsnNode> condition, final Runnable whenFound) {
        AbstractInsnNode instruction;

        while (iterator.hasPrevious()) {
            instruction = iterator.previous();

            if (condition.test(instruction)) {
                whenFound.run();

                return;
            }
        }

        throw new IllegalArgumentException("the specified predicate failed to apply");
    }

    static void findBackward(final ListIterator<AbstractInsnNode> iterator, final Predicate<AbstractInsnNode> condition, final Runnable whenFound, final Runnable alternative) {
        AbstractInsnNode instruction;

        while (iterator.hasPrevious()) {
            instruction = iterator.previous();

            if (condition.test(instruction)) {
                whenFound.run();

                return;
            }
        }

        alternative.run();
    }

    static void findBackward(final ListIterator<AbstractInsnNode> iterator, final Predicate<AbstractInsnNode> condition, final Consumer<AbstractInsnNode> whenFound) {
        AbstractInsnNode instruction;

        while (iterator.hasPrevious()) {
            instruction = iterator.previous();

            if (condition.test(instruction)) {
                whenFound.accept(instruction);

                return;
            }
        }
    }

    static <T> T findBackward(final ListIterator<AbstractInsnNode> iterator, final Predicate<AbstractInsnNode> condition, final Function<AbstractInsnNode, T> whenFound) {
        AbstractInsnNode instruction;

        while (iterator.hasPrevious()) {
            instruction = iterator.previous();

            if (condition.test(instruction)) {
                return whenFound.apply(instruction);
            }
        }

        throw new IllegalArgumentException("the specified predicate failed to apply");
    }

    static void findBackward(final ListIterator<AbstractInsnNode> iterator, final Predicate<AbstractInsnNode> condition, final Consumer<AbstractInsnNode> whenFound, final Runnable alternative) {
        AbstractInsnNode instruction;

        while (iterator.hasPrevious()) {
            instruction = iterator.previous();

            if (condition.test(instruction)) {
                whenFound.accept(instruction);

                return;
            }
        }

        alternative.run();
    }

    static void findForward(final Iterator<AbstractInsnNode> iterator, final Predicate<AbstractInsnNode> condition, final Runnable whenFound) {
        AbstractInsnNode instruction;

        while (iterator.hasNext()) {
            instruction = iterator.next();

            if (condition.test(instruction)) {
                whenFound.run();

                return;
            }
        }

        throw new IllegalArgumentException("the specified predicate failed to apply");
    }

    static void findForward(final Iterator<AbstractInsnNode> iterator, final Predicate<AbstractInsnNode> condition, final Runnable whenFound, final Runnable alternative) {
        AbstractInsnNode instruction;

        while (iterator.hasNext()) {
            instruction = iterator.next();

            if (condition.test(instruction)) {
                whenFound.run();

                return;
            }
        }

        alternative.run();
    }

    static void findForward(final Iterator<AbstractInsnNode> iterator, final Predicate<AbstractInsnNode> condition, final Consumer<AbstractInsnNode> whenFound) {
        AbstractInsnNode instruction;

        while (iterator.hasNext()) {
            instruction = iterator.next();

            if (condition.test(instruction)) {
                whenFound.accept(instruction);

                return;
            }
        }
    }

    static <T> T findForward(final Iterator<AbstractInsnNode> iterator, final Predicate<AbstractInsnNode> condition, final Function<AbstractInsnNode, T> whenFound) {
        AbstractInsnNode instruction;

        while (iterator.hasNext()) {
            instruction = iterator.next();

            if (condition.test(instruction)) {
                return whenFound.apply(instruction);
            }
        }

        throw new IllegalArgumentException("the specified predicate failed to apply");
    }

    static void findForward(final Iterator<AbstractInsnNode> iterator, final Predicate<AbstractInsnNode> condition, final Consumer<AbstractInsnNode> whenFound, final Runnable alternative) {
        AbstractInsnNode instruction;

        while (iterator.hasNext()) {
            instruction = iterator.next();

            if (condition.test(instruction)) {
                whenFound.accept(instruction);

                return;
            }
        }

        alternative.run();
    }

    /**
     * remove instructions between the bounds specified by <b>{@code from}</b> and <b>{@code to}</b>
     *
     * @param iterator an iterator of the instruction list wherein to remove instructions
     * @param from     the {@linkplain AbstractInsnNode#getType() type} of the lower bound (inclusive) of the area to remove
     * @param to       the {@linkplain AbstractInsnNode#getType() type} of the upper bound (exclusive) of the area to remove
     */
    static void removeBetween(final ListIterator<AbstractInsnNode> iterator, final int from, final int to) {
        while (iterator.previous().getType() != from) {
            iterator.remove();
        }

        iterator.remove();

        while (iterator.next().getType() != to) {
            iterator.remove();
        }
    }

    /**
     * remove instructions between the bounds specified by <b>{@code from}</b> and <b>{@code to}</b>
     *
     * @param iterator an iterator of the instruction list wherein to remove instructions
     * @param from     a predicate matching the lower bound (inclusive) of the area to remove
     * @param to       a predicate matching the upper bound (exclusive) of the area to remove
     */
    static void removeBetween(final ListIterator<AbstractInsnNode> iterator, final Predicate<AbstractInsnNode> from, final Predicate<AbstractInsnNode> to) {
        AbstractInsnNode instruction = iterator.previous();

        while (!from.test(instruction)) {
            iterator.remove();

            instruction = iterator.previous();
        }

        iterator.remove();

        instruction = iterator.next();

        while (!to.test(instruction)) {
            iterator.remove();

            instruction = iterator.next();
        }
    }

    /**
     * remove instructions between the bounds specified by <b>{@code from}</b> and <b>{@code to}</b> inclusively
     *
     * @param iterator an iterator of the instruction list wherein to remove instructions
     * @param from     the {@linkplain AbstractInsnNode#getType() type} of the lower bound (inclusive) of the area to remove
     * @param to       the {@linkplain AbstractInsnNode#getType() type} of the upper bound (inclusive) of the area to remove
     */
    static void removeBetweenInclusive(final ListIterator<AbstractInsnNode> iterator, final int from, final int to) {
        while (iterator.previous().getType() != from) {
            iterator.remove();
        }

        iterator.remove();

        while (iterator.next().getType() != to) {
            iterator.remove();
        }

        iterator.remove();
    }

    /**
     * remove instructions between the bounds specified by <b>{@code from}</b> and <b>{@code to}</b> inclusively
     *
     * @param iterator an iterator of the instruction list wherein to remove instructions
     * @param from     a predicate matching the lower bound (inclusive) of the area to remove
     * @param to       a predicate matching the upper bound (inclusive) of the area to remove
     */
    static void removeBetweenInclusive(final ListIterator<AbstractInsnNode> iterator, final Predicate<AbstractInsnNode> from, final Predicate<AbstractInsnNode> to) {
        AbstractInsnNode instruction = iterator.previous();

        while (!from.test(instruction)) {
            iterator.remove();

            instruction = iterator.previous();
        }

        iterator.remove();

        instruction = iterator.next();

        while (!to.test(instruction)) {
            iterator.remove();

            instruction = iterator.next();
        }

        iterator.remove();
    }

    /**
     * remove instructions between the bounds specified by <b>{@code from}</b> and <b>{@code to}</b> exclusively
     *
     * @param iterator an iterator of the instruction list wherein to remove instructions
     * @param from     the {@linkplain AbstractInsnNode#getType() type} of the lower bound (exclusive) of the area to remove
     * @param to       the {@linkplain AbstractInsnNode#getType() type} of the upper bound (exclusive) of the area to remove
     */
    static void removeBetweenExclusive(final ListIterator<AbstractInsnNode> iterator, final int from, final int to) {
        while (iterator.previous().getType() != from) {
            iterator.remove();
        }

        iterator.next();

        while (iterator.next().getType() != to) {
            iterator.remove();
        }
    }

    /**
     * remove instructions between the bounds specified by <b>{@code from}</b> and <b>{@code to}</b> exclusively
     *
     * @param iterator an iterator of the instruction list wherein to remove instructions
     * @param from     a predicate matching the lower bound (exclusive) of the area to remove
     * @param to       a predicate matching the upper bound (exclusive) of the area to remove
     */
    static void removeBetweenExclusive(final ListIterator<AbstractInsnNode> iterator, final Predicate<AbstractInsnNode> from, final Predicate<AbstractInsnNode> to) {
        AbstractInsnNode instruction = iterator.previous();

        while (!from.test(instruction)) {
            iterator.remove();

            instruction = iterator.previous();
        }

        iterator.next();

        instruction = iterator.next();

        while (!to.test(instruction)) {
            iterator.remove();

            instruction = iterator.next();
        }
    }

    static ReferenceArrayList<AbstractInsnNode> getInstructions(final InsnList instructions) {
        final ReferenceArrayList<AbstractInsnNode> list = new ReferenceArrayList<>();
        AbstractInsnNode instruction = instructions.getFirst();

        while (instruction != null) {
            list.add(instruction);

            instruction = instruction.getNext();
        }

        return list;
    }

    static boolean equals(final Object object, final Object other) {
        if (object == other) {
            return true;
        }

        if (object == null) {
            return false;
        }

        if (object instanceof Object[] && other instanceof Object[]) {
            return equals((Object[]) object, (Object[]) other);
        }

        if (object instanceof List && other instanceof List) {
            return equals((List<?>) object, (List<?>) other);
        }

        if (object instanceof AbstractInsnNode && other instanceof AbstractInsnNode) {
            return equals((AbstractInsnNode) object, (AbstractInsnNode) other);
        }

        if (object instanceof AnnotationVisitor) {
            return equals((AnnotationVisitor) object, (AnnotationVisitor) other);
        }

        return Objects.equals(object, other);
    }

    static boolean equals(final Object[] array, final Object[] other) {
        if (array == other) {
            return true;
        }

        if (array == null) {
            return false;
        }

        final int length = array.length;

        if (length != other.length) {
            return false;
        }

        for (int i = 0; i < length; i++) {
            if (!equals(array[i], other[i])) {
                return false;
            }
        }

        return true;
    }

    static boolean equals(final List<?> list, final List<?> other) {
        if (list == other) {
            return true;
        }

        if (list == null) {
            return false;
        }

        final int size = list.size();

        if (size != other.size()) {
            return false;
        }

        for (int i = 0; i != size; i++) {
            if (!equals(list.get(i), other.get(i))) {
                return false;
            }
        }

        return true;
    }

    static boolean equalsTypeAnnotations(final List<TypeAnnotationNode> annotations, final List<TypeAnnotationNode> other) {
        if (annotations == other) {
            return true;
        }

        if (annotations == null) {
            return false;
        }

        final int size = annotations.size();

        if (size != other.size()) {
            return false;
        }

        for (int i = 0; i != size; i++) {
            if (!equals(annotations.get(i), other.get(i))) {
                return false;
            }
        }

        return true;
    }

    static boolean equals(final InsnList instructions, final InsnList otherInstructions) {
        return equals(instructions, otherInstructions, false);
    }

    static boolean equals(final InsnList instructions, final InsnList otherInstructions, final boolean compareAnnotations) {
        if (instructions == otherInstructions) {
            return true;
        }

        if (instructions == null) {
            return false;
        }

        final int size = instructions.size();

        if (size != otherInstructions.size()) {
            return false;
        }

        AbstractInsnNode instruction = instructions.getFirst();
        AbstractInsnNode otherInstruction = otherInstructions.getFirst();

        while (instruction != null) {
            if (!equals(instruction, otherInstruction, compareAnnotations)) {
                return false;
            }

            instruction = instruction.getNext();
            otherInstruction = otherInstruction.getNext();
        }

        return true;
    }

    static boolean equals(final AbstractInsnNode instruction, final AbstractInsnNode other) {
        return equals(instruction, other, false);
    }

    static boolean equals(final AbstractInsnNode instruction, final AbstractInsnNode other, final boolean compareAnnotations) {
        if (instruction == other) {
            return true;
        }

        if (instruction == null) {
            return false;
        }

        final int opcode = instruction.getOpcode();
        final int otherOpcode = other.getOpcode();

        if (opcode != otherOpcode) {
            return false;
        }

        if (instruction.getType() == other.getType()) {
            if (compareAnnotations
                && (!equalsTypeAnnotations(instruction.invisibleTypeAnnotations, other.visibleTypeAnnotations)
                || !equalsTypeAnnotations(instruction.invisibleTypeAnnotations, other.visibleTypeAnnotations))) {
                return false;
            }

            switch (instruction.getType()) {
                case AbstractInsnNode.INSN:
                case AbstractInsnNode.LABEL:
                    return false;
                case AbstractInsnNode.INT_INSN:
                    return ((IntInsnNode) instruction).operand == ((IntInsnNode) other).operand;
                case AbstractInsnNode.VAR_INSN:
                    return ((VarInsnNode) instruction).var == ((VarInsnNode) other).var;
                case AbstractInsnNode.TYPE_INSN:
                    return Objects.equals(((TypeInsnNode) instruction).desc, ((TypeInsnNode) other).desc);
                case AbstractInsnNode.FIELD_INSN:
                    final FieldInsnNode fieldInstruction = (FieldInsnNode) instruction;
                    final FieldInsnNode otherFieldInstruction = (FieldInsnNode) other;

                    return Objects.equals(fieldInstruction.name, otherFieldInstruction.name)
                        && Objects.equals(fieldInstruction.desc, otherFieldInstruction.desc)
                        && Objects.equals(fieldInstruction.owner, otherFieldInstruction.owner);
                case AbstractInsnNode.METHOD_INSN:
                    final MethodInsnNode methodInstruction = (MethodInsnNode) instruction;
                    final MethodInsnNode otherMethodInstruction = (MethodInsnNode) other;

                    return Objects.equals(methodInstruction.name, otherMethodInstruction.name)
                        && Objects.equals(methodInstruction.owner, otherMethodInstruction.owner)
                        && Objects.equals(methodInstruction.desc, otherMethodInstruction.desc)
                        && methodInstruction.itf == otherMethodInstruction.itf;
                case AbstractInsnNode.INVOKE_DYNAMIC_INSN:
                    final InvokeDynamicInsnNode invokeDynamicInstruction = (InvokeDynamicInsnNode) instruction;
                    final InvokeDynamicInsnNode otherInvokeDynamicInstruction = (InvokeDynamicInsnNode) other;

                    return Objects.equals(invokeDynamicInstruction.name, otherInvokeDynamicInstruction.name)
                        && Objects.equals(invokeDynamicInstruction.desc, otherInvokeDynamicInstruction.desc)
                        && equals(invokeDynamicInstruction.bsmArgs, otherInvokeDynamicInstruction.bsmArgs);
                case AbstractInsnNode.JUMP_INSN:
                    return ((JumpInsnNode) instruction).label.getLabel() == ((JumpInsnNode) other).label.getLabel();
                case AbstractInsnNode.LDC_INSN:
                    return Objects.equals(((LdcInsnNode) instruction).cst, ((LdcInsnNode) other).cst);
                case AbstractInsnNode.IINC_INSN:
                    final IincInsnNode iIncInstruction = (IincInsnNode) instruction;
                    final IincInsnNode otherIIncInstruction = (IincInsnNode) other;

                    return iIncInstruction.var == otherIIncInstruction.var && iIncInstruction.incr == otherIIncInstruction.incr;
                case AbstractInsnNode.TABLESWITCH_INSN: {
                    final TableSwitchInsnNode tableSwitchInstruction = (TableSwitchInsnNode) instruction;
                    final TableSwitchInsnNode otherTableSwitchInstruction = (TableSwitchInsnNode) other;

                    if (!(tableSwitchInstruction.min == otherTableSwitchInstruction.min
                        && tableSwitchInstruction.max == otherTableSwitchInstruction.max
                        && tableSwitchInstruction.dflt.getLabel() == otherTableSwitchInstruction.dflt.getLabel())) {
                        return false;
                    }

                    final List<LabelNode> labels = tableSwitchInstruction.labels;
                    final List<LabelNode> otherLabels = otherTableSwitchInstruction.labels;

                    final int size = labels.size();

                    if (size != otherLabels.size()) {
                        return false;
                    }

                    for (int i = 0; i != size; i++) {
                        if (labels.get(i) != otherLabels.get(i)) {
                            return false;
                        }
                    }

                    return true;
                }
                case AbstractInsnNode.LOOKUPSWITCH_INSN: {
                    final LookupSwitchInsnNode lookupSwitchInstruction = (LookupSwitchInsnNode) instruction;
                    final LookupSwitchInsnNode otherLookupSwitchInstruction = (LookupSwitchInsnNode) other;

                    if (!(lookupSwitchInstruction.dflt.getLabel() == otherLookupSwitchInstruction.dflt.getLabel())) {
                        return false;
                    }

                    if (!lookupSwitchInstruction.keys.equals(otherLookupSwitchInstruction.keys)) {
                        return false;
                    }

                    final List<LabelNode> labels = lookupSwitchInstruction.labels;
                    final List<LabelNode> otherLabels = otherLookupSwitchInstruction.labels;

                    final int size = labels.size();

                    if (size != otherLabels.size()) {
                        return false;
                    }

                    for (int i = 0; i != size; i++) {
                        if (labels.get(i) != otherLabels.get(i)) {
                            return false;
                        }
                    }

                    return true;
                }
                case AbstractInsnNode.MULTIANEWARRAY_INSN:
                    final MultiANewArrayInsnNode multiANewArrayInstruction = (MultiANewArrayInsnNode) instruction;
                    final MultiANewArrayInsnNode otherMultiANewArrayInstruction = (MultiANewArrayInsnNode) other;

                    return multiANewArrayInstruction.desc.equals(otherMultiANewArrayInstruction.desc);
                case AbstractInsnNode.FRAME:
                    final FrameNode frame = (FrameNode) instruction;
                    final FrameNode otherFrame = (FrameNode) other;

                    return frame.type == otherFrame.type && frame.stack.equals(otherFrame.stack) && frame.local.equals(otherFrame.stack);
                case AbstractInsnNode.LINE:
                    final LineNumberNode line = (LineNumberNode) instruction;
                    final LineNumberNode otherLine = (LineNumberNode) other;

                    return line.line == otherLine.line && line.start.getLabel() == otherLine.start.getLabel();
            }
        }

        return false;
    }

    static boolean equals(final LocalVariableAnnotationNode annotation, final LocalVariableAnnotationNode other) {
        return equals((TypeAnnotationNode) annotation, other) && Objects.equals(annotation.start, other.start) && Objects.equals(annotation.end, other.end) && Objects.equals(annotation.index, other.index);
    }

    static boolean equals(final TypeAnnotationNode annotation, final TypeAnnotationNode other) {
        if (annotation.typeRef != other.typeRef) {
            return false;
        }

        final TypePath path = annotation.typePath;
        final TypePath otherPath = other.typePath;

        if (path != null && otherPath != null) {
            final int length = path.getLength();

            if (length != otherPath.getLength()) {
                return false;
            }

            for (int i = 0; i != length; i++) {
                if (path.getStep(i) != otherPath.getStep(i)) {
                    return false;
                }
            }
        }

        return equals((AnnotationNode) annotation, other);
    }

    static boolean equals(final AnnotationNode annotation, final AnnotationNode other) {
        return Objects.equals(annotation.desc, other.desc) && equals(annotation.values, other.values);
    }

    static boolean equals(final AnnotationVisitor annotation, final AnnotationVisitor other) {
        if (annotation == other) {
            return true;
        }

        if (annotation == null) {
            return false;
        }

        final Class<? extends AnnotationVisitor> klass = annotation.getClass();

        if (klass != other.getClass()) {
            return false;
        }

        switch (CLASS_TO_INT.getInt(klass)) {
            case ANNOTATION_VISITOR:
                return true;
            case ANNOTATION_NODE:
                return equals((AnnotationNode) annotation, (AnnotationNode) other);
            case TYPE_ANNOTATION_NODE:
                return equals((TypeAnnotationNode) annotation, (TypeAnnotationNode) other);
            case LOCAL_VARIABLE_ANNOTATION_NODE:
                return equals((LocalVariableAnnotationNode) annotation, (LocalVariableAnnotationNode) other);
            default:
                return annotation.equals(other);
        }
    }
}
