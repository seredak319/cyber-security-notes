package com.scmp.security.notes;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Builder
public class NotePrivateRequest {
    private Integer id;
    private String password;
}
