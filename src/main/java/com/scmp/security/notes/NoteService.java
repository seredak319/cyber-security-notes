package com.scmp.security.notes;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.AuditorAware;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.util.*;

@Slf4j
@Service
@RequiredArgsConstructor
public class NoteService {

    private final NoteRepository noteRepository;
    private final AuditorAware<Integer> auditorAware;

    private static final String SUCCESS = "Success";
    private static final String FAILED = "Failed";

    public List<NoteResponse> findAllPublicNotes() {
        final List<Note> publicNotes = noteRepository.findAllByIsPublicTrue();
        final List<NoteResponse> publicNoteResponses = new ArrayList<>();
        for (Note note : publicNotes) {
            NoteResponse noteResponse = new NoteResponse();
            noteResponse.setId(note.getId());
            noteResponse.setTitle(note.getTitle());
            noteResponse.setText(note.getText());
            publicNoteResponses.add(noteResponse);
        }
        return publicNoteResponses;
    }

    public List<NoteResponse> findAllPrivateNotes() {
        Optional<Integer> userIdOptional = auditorAware.getCurrentAuditor();

        if (userIdOptional.isPresent()) {
            List<Note> usersNotes = noteRepository.findAllByCreatedBy(userIdOptional.get());
            return usersNotes.stream()
                    .map(this::mapToResponse).toList();
        }

        return List.of();
    }

    public NoteResponse createNote(NoteRequest request) {
        Note note = null;
        if (Boolean.TRUE.equals(!request.getIsEncrypted())) {
            note = buildNoteFromRequest(request);
        } else if (Boolean.TRUE.equals(request.getIsEncrypted()) && request.getPassword() != null) {
            note = buildEncryptedNoteFromRequest(request);
        }
        Note savedNote = noteRepository.save(note);
        NoteResponse response = new NoteResponse();
        response.setStatus(SUCCESS);
        response.setId(savedNote.getId());
        response.setTitle(savedNote.getTitle());
        response.setText(savedNote.getText());
        return response;
    }

    private NoteResponse mapToResponse(Note note) {
        return NoteResponse.builder()
                .status(SUCCESS)
                .id(note.getId())
                .title(note.getTitle())
                .text(note.getText())
                .isEncrypted(note.getIsEncrypted())
                .build();
    }


    // todo updateNote
//    public NoteResponse updateNote(NoteRequest noteRequest) {
//        Optional<Note> optionalNote = noteRepository.findById(noteRequest.getId());
//        if (optionalNote.isPresent()) {
//            Note existingNote = optionalNote.get();
//
//            if (existingNote.getIsEncrypted() && TRUE.equals(noteRequest.getIsEncrypted())) {
//                existingNote.setEncryptionKey(generateEncryptionKey());
//                existingNote.setIv(generateInitializationVector());
//            }
//
//            existingNote.setIsEncrypted(noteRequest.getIsEncrypted());
//            existingNote.setTitle(noteRequest.getTitle());
//            existingNote.setIsPublic(noteRequest.getIsPublic());
//
//            if (existingNote.getIsPublic()) {
//                Note updatedNote = noteRepository.save(existingNote);
//                NoteResponse response = new NoteResponse();
//                response.setId(updatedNote.getId());
//                response.setTitle(updatedNote.getTitle());
//                response.setText(updatedNote.getText());
//                return response;
//            }
//
//            if (existingNote.getIsEncrypted()) {
//                existingNote.setPassword(hashPassword(noteRequest.getPassword()));
//                existingNote.setText(encryptNoteText(noteRequest.getText(), existingNote.getEncryptionKey(), existingNote.getIv()));
//            }
//            Note updatedNote = noteRepository.save(existingNote);
//            NoteResponse response = new NoteResponse();
//            response.setStatus(SUCCESS);
//            response.setId(updatedNote.getId());
//            response.setTitle(updatedNote.getTitle());
//            response.setText(updatedNote.getIsEncrypted() ? ENCRYPTED : updatedNote.getText());
//            return response;
//        } else {
//            return NoteResponse.builder()
//                    .status(FAILED)
//                    .build();
//        }
//    }

    public NoteResponse getPrivateNote(NotePrivateRequest notePrivateRequest) {
        Note note = noteRepository.findById(notePrivateRequest.getId()).orElse(null);

        log.debug("IV {}", note.getIv());
        log.debug("Secret {}", note.getEncryptionKey());
        log.debug("Password {}", notePrivateRequest.getPassword());
        log.debug("id {}", notePrivateRequest.getId());

        if (note != null && isPasswordValid(notePrivateRequest.getPassword(), note.getPassword())) {
            String decryptedText = decryptNoteText(note.getText(), notePrivateRequest.getPassword(), note.getEncryptionKey(), note.getIv());
            NoteResponse response = new NoteResponse();
            response.setTitle(note.getTitle());
            response.setText(decryptedText);
            return response;
        } else {
            return null;
        }
    }

    private Note buildNoteFromRequest(NoteRequest request) {
        Note note = new Note();
        note.setTitle(request.getTitle());
        note.setText(request.getText());
        note.setIsPublic(request.getIsPublic());
        note.setPassword(hashPassword(request.getPassword()));
        note.setIsEncrypted(false);
        return note;
    }

    private static String encryptNoteText(String plainText, String password, String encryptionKey, String iv) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            SecretKeySpec keySpec = generateKey(password, encryptionKey);
            byte[] ivBytes = Base64.getDecoder().decode(iv);
            IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
            byte[] encrypted = cipher.doFinal(plainText.getBytes());
            return Base64.getEncoder().encodeToString(encrypted);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
                 InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
            return null;
        }
    }

    private static String decryptNoteText(String cipherText, String password, String encryptionKey, String iv) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            SecretKeySpec keySpec = generateKey(password, encryptionKey);
            byte[] ivBytes = Base64.getDecoder().decode(iv);
            IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
            byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(cipherText));
            return new String(decrypted);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
                 InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
            return null;
        }
    }

    private static SecretKeySpec generateKey(String password, String encryptionKey) throws NoSuchAlgorithmException {
        String concatenatedKey = password + encryptionKey;
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] keyBytes = digest.digest(concatenatedKey.getBytes());

        // Ensure key length is 16 bytes (128 bits) for AES encryption
        if (keyBytes.length != 16) {
            if (keyBytes.length > 16) {
                return new SecretKeySpec(Arrays.copyOf(keyBytes, 16), "AES");
            } else {
                // Pad key with zeros if it's less than 16 bytes
                byte[] paddedKey = Arrays.copyOf(keyBytes, 16);
                return new SecretKeySpec(paddedKey, "AES");
            }
        } else {
            return new SecretKeySpec(keyBytes, "AES");
        }
    }

    private static String generateRandomKey() {
        SecureRandom random = new SecureRandom();
        byte[] key = new byte[16];
        random.nextBytes(key);
        return Base64.getEncoder().encodeToString(key);
    }

    private static String generateRandomIV() {
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[16];
        random.nextBytes(iv);
        return Base64.getEncoder().encodeToString(iv);
    }

    private boolean isPasswordValid(String inputPassword, String storedPassword) {
        BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        return passwordEncoder.matches(inputPassword, storedPassword);
    }

    private String hashPassword(String password) {
        if (password == null || password.equals("")) {
            return null;
        }

        BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        return passwordEncoder.encode(password);
    }


    private Note buildEncryptedNoteFromRequest(NoteRequest request) {
        Note note = new Note();
        note.setTitle(request.getTitle());
        var key = generateRandomKey();
        var IV = generateRandomIV();
        var encrypted = encryptNoteText(request.getText(), request.getPassword(), key, IV);
        note.setText(encrypted);
        note.setIsPublic(false);
        note.setPassword(hashPassword(request.getPassword()));
        log.debug("key " + key);
        log.debug("IV " + IV);
        log.debug("password " + request.getPassword());
        log.debug("text plain " + request.getText());
        log.debug("text encrypted " + encrypted);
        note.setEncryptionKey(key);
        note.setIv(IV);
        note.setIsEncrypted(true);
        return note;
    }

    public void deleteById(Integer id) {
        noteRepository.deleteById(id);
    }
}
