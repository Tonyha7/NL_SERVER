using System;
using System.Collections.Generic;

namespace NL_SERVER.FlatBuffers
{
    /// <summary>
    /// Opaque reference to a position in the output buffer.
    /// Stores the used_space() at the time the object was created.
    /// </summary>
    public struct Ref
    {
        public uint Value { get; }

        public Ref(uint value) => Value = value;

        public static Ref Dummy() => new Ref(0);
    }

    /// <summary>
    /// Custom FlatBuffer builder matching Google C++ FlatBuffers binary layout.
    /// Fields are written directly to the output buffer (no data stack), so
    /// objects created between start_table/end_table (like strings) become part
    /// of the table's contiguous byte range — matching the C++ builder exactly.
    /// </summary>
    public class FlatccBuilder
    {
        // --- Buffer State ---
        private byte[] _buf;
        private int _head;
        private int _minAlign;
        private bool _forceDefaults;

        // --- Current Table Construction ---
        private int _tableStart;
        private int _fieldCount;
        private List<(int fieldId, int usedSpace)> _fields;
        private bool _inTable;

        // --- Vtable Deduplication ---
        private List<int> _vtables;

        public FlatccBuilder(int initialCapacity = 1024)
        {
            _buf = new byte[initialCapacity];
            _head = initialCapacity;
            _minAlign = 1;
            _forceDefaults = false;
            _tableStart = 0;
            _fieldCount = 0;
            _fields = new List<(int, int)>();
            _inTable = false;
            _vtables = new List<int>();
        }

        public void ForceDefaults(bool value) => _forceDefaults = value;

        // ---------------------------------------------------------------
        // Buffer Management
        // ---------------------------------------------------------------

        private int UsedSpace() => _buf.Length - _head;

        private void Grow(int additional)
        {
            if (_head >= additional)
                return;

            int needed = additional - _head;
            int newCap = NextPowerOfTwo(_buf.Length + needed);
            int growBy = newCap - _buf.Length;

            byte[] newBuf = new byte[newCap];
            Array.Copy(_buf, _head, newBuf, _head + growBy, _buf.Length - _head);
            _head += growBy;
            _buf = newBuf;
        }

        private static int NextPowerOfTwo(int value)
        {
            // Bit manipulation to find next power of two
            value--;
            value |= value >> 1;
            value |= value >> 2;
            value |= value >> 4;
            value |= value >> 8;
            value |= value >> 16;
            return value + 1;
        }

        private void Align(int align)
        {
            int used = UsedSpace();
            int pad = (align - (used % align)) % align;
            if (pad > 0)
            {
                Grow(pad);
                _head -= pad;
            }
            if (align > _minAlign)
                _minAlign = align;
        }

        private void PushBytes(byte[] data)
        {
            Grow(data.Length);
            _head -= data.Length;
            Array.Copy(data, 0, _buf, _head, data.Length);
        }

        private void PushU32(uint value)
        {
            PushBytes(BitConverter.GetBytes(value));
        }

        private void WriteI32At(int absIndex, int value)
        {
            byte[] bytes = BitConverter.GetBytes(value);
            Array.Copy(bytes, 0, _buf, absIndex, 4);
        }

        /// <summary>
        /// Push N zero bytes into the output buffer (for reproducing alignment gaps).
        /// </summary>
        public void PushZeros(int count)
        {
            Grow(count);
            _head -= count;
            // Buffer is already zeroed from allocation
        }

        // ---------------------------------------------------------------
        // Strings
        // ---------------------------------------------------------------

        /// <summary>
        /// Create a null-terminated string with u32 length prefix.
        /// Layout (forward): [len:u32] [bytes...] [0x00] [padding]
        /// Padding matches C++ PreAlign(len+1, 4): pad so (used + len + 1) is 4-aligned.
        /// </summary>
        public Ref CreateString(string s)
        {
            byte[] bytes = System.Text.Encoding.UTF8.GetBytes(s);
            int len = bytes.Length;
            
            // C++ PreAlign: pad so (used_space + len + 1) is 4-aligned.
            int dataLen = len + 1; // data bytes + null terminator
            int pad = (4 - ((UsedSpace() + dataLen) % 4)) % 4;
            
            if (4 > _minAlign)
                _minAlign = 4;

            int total = pad + dataLen + 4; // padding + data + null + count
            Grow(total);
            
            _head -= pad;           // trailing padding
            _head -= 1;             // null terminator
            _head -= len;
            Array.Copy(bytes, 0, _buf, _head, len);
            
            PushU32((uint)len);

            return new Ref((uint)UsedSpace());
        }

        // ---------------------------------------------------------------
        // Vectors
        // ---------------------------------------------------------------

        /// <summary>
        /// Create a byte vector: [count:u32] [data...] [padding]
        /// Padding matches C++ PreAlign(len, 4): pad so (used + len) is 4-aligned.
        /// </summary>
        public Ref CreateVectorU8(byte[] data)
        {
            int len = data.Length;
            
            // C++ PreAlign: pad so (used_space + len) is 4-aligned.
            int pad = (4 - ((UsedSpace() + len) % 4)) % 4;
            
            if (4 > _minAlign)
                _minAlign = 4;

            int total = pad + len + 4;
            Grow(total);
            
            _head -= pad;
            _head -= len;
            Array.Copy(data, 0, _buf, _head, len);
            
            PushU32((uint)len);

            return new Ref((uint)UsedSpace());
        }

        /// <summary>
        /// Create a vector of offsets: [count:u32] [offset0:u32] [offset1:u32] ...
        /// </summary>
        public Ref CreateVectorOffsets(Ref[] refs)
        {
            int count = refs.Length;
            int dataSize = count * 4;
            
            // data_size is always a multiple of 4, so PreAlign(data_size, 4) = align(4).
            int pad = (4 - ((UsedSpace() + dataSize) % 4)) % 4;
            
            if (4 > _minAlign)
                _minAlign = 4;

            int total = pad + dataSize + 4;
            Grow(total);
            
            _head -= pad;
            _head -= dataSize;
            int dataStart = _head;
            
            PushU32((uint)count);

            for (int i = 0; i < refs.Length; i++)
            {
                uint slotUsedSpace = (uint)((_buf.Length - dataStart - i * 4));
                uint rel = slotUsedSpace - refs[i].Value;
                byte[] offset = BitConverter.GetBytes(rel);
                Array.Copy(offset, 0, _buf, dataStart + i * 4, 4);
            }

            return new Ref((uint)UsedSpace());
        }

        // ---------------------------------------------------------------
        // Tables — Fields Written Directly to Output Buffer
        // ---------------------------------------------------------------

        /// <summary>
        /// Begin constructing a table with up to fieldCount fields.
        /// </summary>
        public void StartTable(int fieldCount)
        {
            _inTable = true;
            _tableStart = UsedSpace();
            _fieldCount = fieldCount;
            _fields.Clear();
        }

        /// <summary>
        /// Add a u32 scalar field to the current table.
        /// </summary>
        public void TableAddU32(int id, uint value, uint defaultValue)
        {
            if (!_forceDefaults && value == defaultValue)
                return;

            Align(4);
            PushU32(value);
            _fields.Add((id, UsedSpace()));
        }

        /// <summary>
        /// Add an offset field (pointing to a string, vector, or table).
        /// </summary>
        public void TableAddOffset(int id, Ref r)
        {
            Align(4);
            
            // Relative offset: distance from this field's position to the target.
            // rel = used_space_after_align + 4 - r.Value
            //     = (field_forward_pos is at total - used - 4, target at total - r.Value)
            //     = target_forward - field_forward = used + 4 - r.Value
            uint rel = (uint)(UsedSpace() + 4 - r.Value);
            PushU32(rel);
            _fields.Add((id, UsedSpace()));
        }

        /// <summary>
        /// Finish the current table. Emits soffset + vtable to the output buffer.
        /// </summary>
        public Ref EndTable()
        {
            // Push soffset placeholder (4 bytes) — this is the table's "start" in the
            // forward buffer. All field offsets in the vtable are relative to this point.
            Align(4);
            PushU32(0); // placeholder
            int vtLoc = UsedSpace();
            int tableAbs = _head; // absolute position of soffset in buf

            int tableSize = vtLoc - _tableStart;

            // Build vtable: [vt_size:u16] [table_size:u16] [field0:u16] [field1:u16] ...
            int vtHeader = 4;
            int vtFullSize = vtHeader + _fieldCount * 2;
            byte[] vtable = new byte[vtFullSize];
            
            // table_size header filled below after trimming
            byte[] tableSizeBytes = BitConverter.GetBytes((ushort)tableSize);
            Array.Copy(tableSizeBytes, 0, vtable, 2, 2);

            foreach (var field in _fields)
            {
                ushort fieldOff = (ushort)(vtLoc - field.usedSpace);
                byte[] offset = BitConverter.GetBytes(fieldOff);
                Array.Copy(offset, 0, vtable, vtHeader + field.fieldId * 2, 2);
            }

            // Trim trailing zero slots from vtable (matching C++ builder behavior).
            int vtSize = vtFullSize;
            while (vtSize > vtHeader)
            {
                int slotOff = vtSize - 2;
                if (vtable[slotOff] != 0 || vtable[slotOff + 1] != 0)
                    break;
                vtSize -= 2;
            }
            byte[] vtableResized = new byte[vtSize];
            Array.Copy(vtable, vtableResized, vtSize);
            
            byte[] vtSizeBytes = BitConverter.GetBytes((ushort)vtSize);
            Array.Copy(vtSizeBytes, 0, vtableResized, 0, 2);

            // Vtable deduplication.
            int? existingVtableUsed = null;
            foreach (int vtPos in _vtables)
            {
                int vtAbs = _buf.Length - vtPos;
                if (vtAbs + 2 > _buf.Length)
                    continue;

                ushort existingSize = BitConverter.ToUInt16(_buf, vtAbs);
                if (existingSize != vtSize)
                    continue;

                if (vtAbs + existingSize > _buf.Length)
                    continue;

                // Full byte comparison
                bool match = true;
                for (int i = 0; i < existingSize; i++)
                {
                    if (_buf[vtAbs + i] != vtableResized[i])
                    {
                        match = false;
                        break;
                    }
                }

                if (match)
                {
                    existingVtableUsed = vtPos;
                    break;
                }
            }

            int soffset;
            if (existingVtableUsed.HasValue)
            {
                int vtableAbs = _buf.Length - existingVtableUsed.Value;
                soffset = tableAbs - vtableAbs;
            }
            else
            {
                // Emit new vtable inline, immediately before the table.
                PushBytes(vtableResized);
                int vtableAbs = _head;
                _vtables.Add(_buf.Length - vtableAbs);
                soffset = tableAbs - vtableAbs;
            }

            // Patch soffset.
            WriteI32At(tableAbs, soffset);
            _inTable = false;

            return new Ref((uint)vtLoc);
        }

        // ---------------------------------------------------------------
        // Finish
        // ---------------------------------------------------------------

        /// <summary>
        /// Finish the buffer: prepend root offset, return final bytes.
        /// </summary>
        public byte[] FinishMinimal(Ref root)
        {
            int align = Math.Max(_minAlign, 4);
            int used = UsedSpace();
            int total = 4 + used;
            int paddedTotal = (total + align - 1) & ~(align - 1);
            int pad = paddedTotal - total;
            
            if (pad > 0)
            {
                Grow(pad);
                _head -= pad;
            }

            // Root offset = distance from byte 0 to the root table.
            int rootAbs = _buf.Length - (int)root.Value;
            int rootFinalPos = rootAbs - _head + 4;
            PushU32((uint)rootFinalPos);

            byte[] result = new byte[_buf.Length - _head];
            Array.Copy(_buf, _head, result, 0, result.Length);
            return result;
        }

        /// <summary>
        /// Finish building and return the buffer.
        /// </summary>
        public byte[] Finish(Ref root) => FinishMinimal(root);
    }
}