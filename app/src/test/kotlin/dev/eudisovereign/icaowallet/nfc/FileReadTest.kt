package dev.eudisovereign.icaowallet.nfc

import java.io.IOException
import net.sf.scuba.smartcards.FileInfo
import net.sf.scuba.smartcards.FileSystemStructured
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class FileReadTest {

    private class FakeFileSystem(private val declaredLength: Int, private val content: ByteArray) : FileSystemStructured {
        var reads = 0
            private set

        private val path = arrayOf<FileInfo>(object : FileInfo() {
            override fun getFID(): Short = 0x0101
            override fun getFileLength(): Int = declaredLength
        })

        override fun selectFile(fid: Short) = Unit

        override fun readBinary(offset: Int, length: Int): ByteArray {
            reads++
            return content.copyOfRange(offset, minOf(content.size, offset + length))
        }

        override fun getSelectedPath(): Array<FileInfo> = path
    }

    @Test
    fun readsTheDeclaredLengthInBlocks() {
        val content = ByteArray(600) { it.toByte() }
        val fileSystem = FakeFileSystem(content.size, content)
        assertArrayEquals(content, DniEPassportReader.readAll(fileSystem, 0x0101))
        assertEquals(3, fileSystem.reads)
    }

    @Test
    fun implausibleDeclaredLengthIsRejectedBeforeAnyRead() {
        val fileSystem = FakeFileSystem(Int.MAX_VALUE, ByteArray(0))
        val e = assertThrows(IOException::class.java) { DniEPassportReader.readAll(fileSystem, 0x0101) }
        assertEquals("EF 0101: declared length is implausible", e.message)
        assertEquals(0, fileSystem.reads)
        assertThrows(IOException::class.java) {
            DniEPassportReader.readAll(FakeFileSystem(DniEPassportReader.MAX_FILE_LENGTH + 1, ByteArray(0)), 0x0101)
        }
    }

    @Test
    fun missingLengthIsRejected() {
        assertThrows(IOException::class.java) { DniEPassportReader.readAll(FakeFileSystem(0, ByteArray(0)), 0x0101) }
    }
}
