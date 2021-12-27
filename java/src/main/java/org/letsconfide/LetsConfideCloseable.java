package org.letsconfide;

/**
 * A closable whose close method throws {@link LetsConfideException}.
 */
public interface LetsConfideCloseable extends AutoCloseable
{
    @Override
    void close() throws LetsConfideException;
}
