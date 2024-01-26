package com.scmp.security.notes;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Slf4j
@RestController
@RequestMapping("/api/v1/notes")
@RequiredArgsConstructor
public class NoteController {

    private final NoteService service;

    @PostMapping("/create")
    public ResponseEntity<NoteResponse> createNote(
            @RequestBody NoteRequest request
    ) {
        log.debug("/create");
        return ResponseEntity.ok(service.createNote(request));
    }

    @GetMapping("/public")
    public ResponseEntity<List<NoteResponse>> findAllPublicNotes() {
        return ResponseEntity.ok(service.findAllPublicNotes());
    }

    @GetMapping("/private")
    public ResponseEntity<List<NoteResponse>> findAllPrivateNotes() {
        return ResponseEntity.ok(service.findAllPrivateNotes());
    }

//    @PutMapping("/update")
//    public ResponseEntity<NoteResponse> updateNoteById(@RequestBody NoteRequest noteRequest) {
//        return ResponseEntity.ok(service.updateNote(noteRequest));
//    }

    @PostMapping("/decrypt")
    public ResponseEntity<NoteResponse> getPrivateNote(@RequestBody NotePrivateRequest notePrivateRequest) {
        return ResponseEntity.ok(service.getPrivateNote(notePrivateRequest));
    }

    @DeleteMapping("/delete/{id}")
    public ResponseEntity deleteById(@PathVariable Integer id) {
        log.debug("/delete/{}", id);
        service.deleteById(id);
        return ResponseEntity.ok().build();
    }
}
