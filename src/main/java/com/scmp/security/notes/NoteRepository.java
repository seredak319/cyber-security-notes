package com.scmp.security.notes;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface NoteRepository extends JpaRepository<Note, Integer> {

    List<Note> findAllByIsPublicTrue();

    List<Note> findAllByCreatedBy(Integer userId);
}
