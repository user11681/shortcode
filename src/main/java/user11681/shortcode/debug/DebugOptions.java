package user11681.shortcode.debug;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DebugOptions {
    public static final Logger DEFAULT_LOGGER = LogManager.getLogger("Shortcode");
    public static final boolean DEFAULT_UPPERCASE = false;
    public static final boolean DEFAULT_INDEXES = true;
    public static final String DEFAULT_INDENTATION = "  ";

    public boolean uppercase;
    public boolean indexes;
    public String indentation;
    public Logger logger;

    protected DebugOptions() {
        this(DEFAULT_UPPERCASE, DEFAULT_INDEXES, DEFAULT_INDENTATION, DEFAULT_LOGGER);
    }

    protected DebugOptions(final boolean uppercase, final boolean indexes, final String indentation, final Logger logger) {
        this.uppercase = uppercase;
        this.indexes = indexes;
        this.indentation = indentation;
        this.logger = logger;
    }

    public static DebugOptions defaultOptions() {
        return new DebugOptions();
    }

    public DebugOptions uppercase() {
        return new DebugOptions(true, this.indexes, this.indentation, this.logger);
    }

    public DebugOptions indexes() {
        return new DebugOptions(this.uppercase, true, this.indentation, this.logger);
    }

    public DebugOptions indentation(final int indentation) {
        final StringBuilder indentationBuilder = new StringBuilder();

        for (int i = 0; i < indentation; i++) {
            indentationBuilder.append(' ');
        }

        return new DebugOptions(this.uppercase, this.indexes, indentationBuilder.toString(), this.logger);
    }

    public DebugOptions logger(final Logger logger) {
        return new DebugOptions(this.uppercase, this.indexes, this.indentation, logger);
    }
}
