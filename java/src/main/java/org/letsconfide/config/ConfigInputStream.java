package org.letsconfide.config;

import org.letsconfide.LetsConfideException;

import javax.annotation.Nonnull;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * Stream used for reading the configuration file.<BR>
 * For security reasons this stream restricts the maximum number of bytes that can be read.
 */
public class ConfigInputStream extends FilterInputStream
{

    /**
     * The maximum amount of data that can be read by this stream.
     */
    // TODO: make this configurable property
    private final static long MAX_STREAM_LENGTH = 256*1024;
    private long count;
    private long mark = -1;

    /**
     * Creates a new stream by wrapping an existing stream.
     * @param in The stream being wrapped
     */
    public ConfigInputStream(InputStream in)
    {
        super(in);
    }

    @Override
    public int read() throws IOException
    {
        int result = in.read();
        if (result != -1) {
            addToCount(1);
        }
        return result;
    }

    @Override
    public int read(@Nonnull byte[] b, int off, int len) throws IOException
    {
        int result = in.read(b, off, len);
        if (result != -1) {
            addToCount(result);
        }
        return result;
    }

    @Override
    public long skip(long n) throws IOException
    {
        long result = in.skip(n);
        addToCount(result);
        return result;
    }

    @Override
    public synchronized void mark(int readLimit)
    {
        in.mark(readLimit);
        mark = count;
        // it's okay to mark even if mark isn't supported, as reset won't work
    }

    @Override
    public synchronized void reset() throws IOException
    {
        in.reset();
        setCount(mark);
    }

    private void addToCount(long delta)
    {
        setCount(count+delta);
    }

    private void setCount(long count)
    {
        if(count > MAX_STREAM_LENGTH)
        {
            throw new LetsConfideException("The config is too large.");
        }
        this.count = count;
    }
}