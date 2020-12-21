package user11681.shortcode.instruction;

import org.objectweb.asm.tree.MethodInsnNode;

public class MethodInvocation {
    public final String owner;
    public final String name;
    public final String descriptor;

    public MethodInvocation(final MethodInsnNode instruction) {
        this.owner = instruction.owner;
        this.name = instruction.name;
        this.descriptor = instruction.desc;
    }
}
