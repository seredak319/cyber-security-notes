package com.scmp.security.notes;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class NoteResponse {

    private String status;
    private Integer id;
    private String title;
    private String text;
    private Boolean isEncrypted;
}
