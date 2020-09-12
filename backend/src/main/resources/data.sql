insert into revocation_reason (name) value ('Private key compromised');
insert into revocation_reason (name) value ('Invalid request for issuing certificate');
insert into revocation_reason (name) value ('Unintentionally signed certificate');
insert into revocation_reason (name) value ('Subject misconduct');

insert into authority (name) value ('ROLE_ADMIN');
insert into admin (username, password ) value ('admin@gmail.com', '$2a$10$aMBAEXjwqcavdNT373EM7.hlk2MWp1SNYCZ5NWk/Dytyf/xPsI02a');
insert into admin_authority (admin_id, authority_id) value (1,1);

# login credentials
# email: admin@gmail.com
# password: admin
