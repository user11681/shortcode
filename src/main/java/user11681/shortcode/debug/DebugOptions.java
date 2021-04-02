package user11681.shortcode.debug;

public class DebugOptions {
    public static final Printer DEFAULT_LOGGER = System.out::println;
    public static final boolean DEFAULT_UPPERCASE = false;
    public static final boolean DEFAULT_INDEXES = true;
    public static final String DEFAULT_INDENTATION = "  ";

    public boolean uppercase;
    public boolean indexes;
    public String indentation;
    public Printer printer;

    protected DebugOptions() {
        this(DEFAULT_UPPERCASE, DEFAULT_INDEXES, DEFAULT_INDENTATION, DEFAULT_LOGGER);
    }

    protected DebugOptions(boolean uppercase, boolean indexes, String indentation, Printer printer) {
        this.uppercase = uppercase;
        this.indexes = indexes;
        this.indentation = indentation;
        this.printer = printer;
    }

    public static DebugOptions defaultOptions() {
        return new DebugOptions();
    }

    public DebugOptions uppercase() {
        return new DebugOptions(true, this.indexes, this.indentation, this.printer);
    }

    public DebugOptions indexes() {
        return new DebugOptions(this.uppercase, true, this.indentation, this.printer);
    }

    public DebugOptions indentation(int indentation) {
        StringBuilder indentationBuilder = new StringBuilder();

        for (int i = 0; i < indentation; i++) {
            indentationBuilder.append(' ');
        }

        return new DebugOptions(this.uppercase, this.indexes, indentationBuilder.toString(), this.printer);
    }

    public DebugOptions printer(Printer printer) {
        return new DebugOptions(this.uppercase, this.indexes, this.indentation, printer);
    }
}
