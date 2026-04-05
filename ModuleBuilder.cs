using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Google.FlatBuffers;
using LZ4;
using NL_SERVER.FlatBuffers;

namespace NL_SERVER
{
    public static class ModuleBuilder
    {
        private static byte[] _cachedSkinData = null;

        public class ExtractedLanguage
        {
            public string Code { get; set; }
            public string EnglishName { get; set; }
            public string NativeName { get; set; }
            public string TranslationsJson { get; set; }
        }

        private static List<ExtractedLanguage> _cachedLanguages = null;

        public static List<ExtractedLanguage> GetLanguages()
        {
            if (_cachedLanguages != null) return _cachedLanguages;
            _cachedLanguages = new List<ExtractedLanguage>();
            try
            {
                var encryptedFlat = global::NL_SERVER.ModuleBin.Data;
                var compressedFlat = DecryptAES128CBC(encryptedFlat);
                var flat = DecompressLZ4WithHeader(compressedFlat);
                var bb = new global::Google.FlatBuffers.ByteBuffer(flat);
                var wrapper = nl.ModuleWrapper.GetRootAsModuleWrapper(bb);
                var payload = wrapper.GetPayloadAsModuleData();
                if (payload.HasValue)
                {
                    for (int i = 0; i < payload.Value.LanguagesLength; i++)
                    {
                        var lang = payload.Value.Languages(i);
                        if (lang.HasValue)
                        {
                            var l = lang.Value;
                            var translationsBytes = l.GetTranslationsArray();
                            string translationsStr = null;
                            if (translationsBytes != null)
                            {
                                if (translationsBytes.Length > 0 && translationsBytes[translationsBytes.Length - 1] == 0)
                                {
                                    translationsStr = System.Text.Encoding.UTF8.GetString(translationsBytes, 0, translationsBytes.Length - 1);
                                }
                                else
                                {
                                    translationsStr = System.Text.Encoding.UTF8.GetString(translationsBytes);
                                }
                            }
                            _cachedLanguages.Add(new ExtractedLanguage
                            {
                                Code = l.Code,
                                EnglishName = l.EnglishName,
                                NativeName = l.NativeName,
                                TranslationsJson = translationsStr
                            });
                        }
                    }
                    Console.WriteLine($"[ModuleBuilder] Successfully extracted {_cachedLanguages.Count} languages.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[ModuleBuilder] Failed to load languages from embedded byte stream: {ex.Message}");
            }
            return _cachedLanguages;
        }

        public static byte[] GetSkinDataBytes()
        {
            if (_cachedSkinData != null) return _cachedSkinData;

            try
            {
                var encryptedFlat = global::NL_SERVER.ModuleBin.Data;
                var compressedFlat = DecryptAES128CBC(encryptedFlat);
                var flat = DecompressLZ4WithHeader(compressedFlat);
                var bb = new global::Google.FlatBuffers.ByteBuffer(flat);
                var wrapper = nl.ModuleWrapper.GetRootAsModuleWrapper(bb);
                var payload = wrapper.GetPayloadAsModuleData();
                if (payload.HasValue)
                {
                    _cachedSkinData = payload.Value.GetSkinDataArray();
                    Console.WriteLine($"[ModuleBuilder] Successfully extracted skin_data ({_cachedSkinData.Length} bytes). First bytes: {BitConverter.ToString(_cachedSkinData.Take(10).ToArray())}");
                    if (_cachedSkinData != null) return _cachedSkinData;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[ModuleBuilder] Failed to load skin_data from embedded byte stream: {ex.Message}");
            }

            _cachedSkinData = MessagePack.MessagePackSerializer.Serialize(new Dictionary<string, object>());
            return _cachedSkinData;
        }
        private static readonly byte[] KEY = new byte[] { 
            0x64, 0x38, 0x31, 0x56, 0x2A, 0x4B, 0x0F, 0x65, 0x25, 0x59, 0x06, 0x14, 0x70, 0x49, 0x4A, 0x7D 
        };
        private static readonly byte[] IV = Encoding.ASCII.GetBytes("5aAxpFpna5QqvYMv");

        public static byte[] BuildUserModule(string username, List<LogEntry> configLogs, List<LogEntry> scriptLogs)
        {
            var b = new FlatccBuilder();
            
            // Phase 1: Log entries
            var configOffsets = new Ref[configLogs.Count];
            for (int i = 0; i < configLogs.Count; i++)
            {
                configOffsets[i] = BuildLogEntryWithGap(b, configLogs[i], 8);
            }
            
            var scriptOffsets = new Ref[scriptLogs.Count];
            for (int i = 0; i < scriptLogs.Count; i++)
            {
                scriptOffsets[i] = BuildLogEntry(b, scriptLogs[i]);
            }
            
            // Phase 2: Language DATA
            var langs = GetLanguages() ?? new List<ExtractedLanguage>();
            var langCodes = new Ref[langs.Count];
            var langEnNames = new Ref[langs.Count];
            var langNativeNames = new Ref[langs.Count];
            var langTranslations = new Ref?[langs.Count];
            
            for (int i = 0; i < langs.Count; i++)
            {
                var lang = langs[i];
                if (!string.IsNullOrEmpty(lang.TranslationsJson))
                {
                    langTranslations[i] = b.CreateString(lang.TranslationsJson);
                }
                langCodes[i] = b.CreateString(lang.Code ?? "");
                langEnNames[i] = b.CreateString(lang.EnglishName ?? "");
                if (lang.NativeName == lang.EnglishName)
                {
                    langNativeNames[i] = langEnNames[i];
                }
                else
                {
                    langNativeNames[i] = b.CreateString(lang.NativeName ?? "");
                }
            }
            
            // Phase 3: extra_data
            b.PushZeros(4);
            var extraData = b.CreateVectorU8(Array.Empty<byte>());
            
            // Phase 3.5: Orphaned string
            b.CreateString("admin");
            
            // Phase 4: skin_data
            var skinDataBytes = GetSkinDataBytes();
            var skinData = b.CreateVectorU8(skinDataBytes); // Return valid empty object using MessagePack
            
            // Phase 5: auth_token
            var authToken = b.CreateString("3JNrQVLU04XQc0aKl563");
            
            // Phase 6: Language TABLES
            var langOffsets = new Ref[langs.Count];
            if (langs.Count == 5)
            {
                int[] creationOrder = { 0, 3, 2, 1, 4 };
                foreach (int idx in creationOrder)
                {
                    langOffsets[idx] = BuildLangTable(b, langCodes[idx], langEnNames[idx], langNativeNames[idx], langTranslations[idx]);
                }
            }
            else
            {
                for (int i = 0; i < langs.Count; i++)
                {
                    langOffsets[i] = BuildLangTable(b, langCodes[i], langEnNames[i], langNativeNames[i], langTranslations[i]);
                }
            }
            
            // Phase 7: Vector offset arrays
            var langVec = b.CreateVectorOffsets(langOffsets);
            var scriptVec = b.CreateVectorOffsets(scriptOffsets);
            var configVec = b.CreateVectorOffsets(configOffsets);
            
            // Phase 8+9: Root table
            b.StartTable(12);
            b.TableAddOffset(4, configVec);
            b.TableAddOffset(5, scriptVec);
            b.TableAddOffset(7, langVec);
            b.TableAddOffset(1, extraData);
            var author = b.CreateString(username);
            b.TableAddOffset(2, author);
            b.TableAddOffset(9, skinData);
            b.TableAddU32(3, 2525176212, 0); // Mock checksum
            b.TableAddU32(8, 1, 0);      // Enabled
            b.TableAddU32(6, 1732096, 0);   // Buffer capacity
            b.TableAddOffset(11, authToken);
            var root = b.EndTable();
            var innerBytes = b.FinishMinimal(root);

            var ob = new FlatBufferBuilder(1024);
            ob.ForceDefaults = true;
            var payloadOffset = nl.ModuleWrapper.CreatePayloadVector(ob, innerBytes);
            nl.ModuleWrapper.StartModuleWrapper(ob);
            nl.ModuleWrapper.AddVersion(ob, 0);
            nl.ModuleWrapper.AddPayload(ob, payloadOffset);
            var outerOffset = nl.ModuleWrapper.EndModuleWrapper(ob);
            ob.Finish(outerOffset.Value);

            var outerBytes = ob.SizedByteArray();

            //var debugDir = "compare_bins_cs";
            //Directory.CreateDirectory(debugDir);
            //File.WriteAllBytes(Path.Combine(debugDir, "server_inner.bin"), innerBytes);
            //File.WriteAllBytes(Path.Combine(debugDir, "server_outer.bin"), outerBytes);

            var compressed = CompressLZ4WithHeader(outerBytes);
            var encrypted = EncryptAES128CBC(compressed);
            //File.WriteAllBytes(Path.Combine(debugDir, "server_encrypted.bin"), encrypted);

            return encrypted;
        }

        private static Ref BuildLogEntry(FlatccBuilder b, LogEntry entry)
        {
            var name = b.CreateString(entry.Name);
            var author = b.CreateString(entry.Author);
            b.StartTable(5);
            b.TableAddU32(0, (uint)entry.EntryId, 0);
            b.TableAddU32(1, (uint)entry.Timestamp, 0);
            b.TableAddOffset(3, name);
            b.TableAddOffset(4, author);
            return b.EndTable();
        }

        private static Ref BuildLogEntryWithGap(FlatccBuilder b, LogEntry entry, int gap)
        {
            var name = b.CreateString(entry.Name);
            var author = b.CreateString(entry.Author);
            b.PushZeros(gap);
            b.StartTable(5);
            b.TableAddU32(0, (uint)entry.EntryId, 0);
            b.TableAddU32(1, (uint)entry.Timestamp, 0);
            b.TableAddOffset(3, name);
            b.TableAddOffset(4, author);
            return b.EndTable();
        }
        
        private static Ref BuildLangTable(FlatccBuilder b, Ref code, Ref enName, Ref nativeName, Ref? translations)
        {
            b.StartTable(7);
            b.TableAddOffset(2, code);
            b.TableAddOffset(4, enName);
            b.TableAddOffset(5, nativeName);
            if (translations.HasValue)
            {
                b.TableAddOffset(6, translations.Value);
            }
            return b.EndTable();
        }

        public static byte[] EncryptAES128CBC(byte[] data)
        {
            using var aes = Aes.Create();
            aes.Key = KEY;
            aes.IV = IV;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            using var encryptor = aes.CreateEncryptor();
            return encryptor.TransformFinalBlock(data, 0, data.Length);
        }
        
        public static byte[] DecryptAES128CBC(byte[] data)
        {
            using var aes = Aes.Create();
            aes.Key = KEY;
            aes.IV = IV;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            using var encryptor = aes.CreateDecryptor();
            return encryptor.TransformFinalBlock(data, 0, data.Length);
        }

        public static byte[] CompressLZ4WithHeader(byte[] data)
        {
            byte[] sizeHeader = BitConverter.GetBytes((uint)data.Length);
            byte[] compressed = LZ4Codec.Encode(data, 0, data.Length);
            
            var outStream = new MemoryStream();
            outStream.Write(sizeHeader, 0, sizeHeader.Length);
            outStream.Write(compressed, 0, compressed.Length);
            return outStream.ToArray();
        }
        
        public static byte[] DecompressLZ4WithHeader(byte[] data)
        {
            int uncompressedSize = BitConverter.ToInt32(data, 0);
            var decompressed = new byte[uncompressedSize];
            LZ4Codec.Decode(data, 4, data.Length - 4, decompressed, 0, uncompressedSize);
            return decompressed;
        }
    }
}