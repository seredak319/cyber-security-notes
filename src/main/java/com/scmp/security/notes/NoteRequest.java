package com.scmp.security.notes;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Builder
public class NoteRequest {

    private Integer id;
    private String title;
    private String text;
    private Boolean isPublic;
    private String password;
    private Boolean isEncrypted;
}
