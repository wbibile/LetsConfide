package org.letsconfide;

/**
 * Exception thrown by ListConfide will be of this type.
 * This Exception is unchecked making it easier to use functions that throw this exception in lambda expressions.
 */
public class LetsConfideException extends RuntimeException
{
    public LetsConfideException()
    {
        super();
    }

    public LetsConfideException(String message)
    {
        super(message);
    }

    public LetsConfideException(String message, Throwable cause)
    {
        super(message, cause);
    }

    public LetsConfideException(Throwable cause)
    {
        super(cause);
    }

}
