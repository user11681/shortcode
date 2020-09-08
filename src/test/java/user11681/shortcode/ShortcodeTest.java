package user11681.shortcode;

import org.junit.jupiter.api.Test;
import org.junit.platform.commons.annotation.Testable;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IntInsnNode;

@Testable
class ShortcodeTest {
    @Test
    void insnTest() {
        final InsnNode i0 = new InsnNode(Opcodes.IDIV);
        final InsnNode i1 = new InsnNode(Opcodes.FMUL);
        final InsnNode i2 = new InsnNode(Opcodes.RETURN);

        assert !Shortcode.equals(i0, i1);
        assert !Shortcode.equals(i0, i2);
        assert !Shortcode.equals(i1, i2);
        assert Shortcode.equals(i1, i1);
    }

    @Test
    void intInsnTest() {
        final IntInsnNode i0 = new IntInsnNode(Opcodes.BIPUSH, 123);
        final IntInsnNode i1 = new IntInsnNode(Opcodes.SIPUSH, 321);
        final IntInsnNode i2 = new IntInsnNode(Opcodes.SIPUSH, 12345);
        final IntInsnNode i3 = new IntInsnNode(Opcodes.ANEWARRAY, 12345);

        assert Shortcode.equals(i0, i0);
        assert !Shortcode.equals(i1, i2);
        assert !Shortcode.equals(i3, i0);
        assert !Shortcode.equals(i2, i1);
    }

    @Test
    void varInsnTest() {
        final FieldInsnNode i0 = new FieldInsnNode(Opcodes.GETSTATIC, "0", "1", "2");
        final FieldInsnNode i1 = new FieldInsnNode(Opcodes.GETFIELD, "2", "1", "0");
        final FieldInsnNode i2 = new FieldInsnNode(Opcodes.GETFIELD, "1", "2", "0");
        final FieldInsnNode i3 = new FieldInsnNode(Opcodes.PUTFIELD, "2", "0", "1");
        final FieldInsnNode i4 = new FieldInsnNode(Opcodes.PUTFIELD, "2", "0", "1");

        assert !Shortcode.equals(i0, i1);
        assert !Shortcode.equals(i2, i1);
        assert !Shortcode.equals(i3, i1);
        assert !Shortcode.equals(i0, i1);
        assert Shortcode.equals(i3, i4);
    }
}