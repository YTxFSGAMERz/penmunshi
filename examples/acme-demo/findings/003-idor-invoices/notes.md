IDOR on GET /api/invoices/{id}. Logged in as a regular customer I can read invoices of other customers by changing the numeric id.
Invoice 1042 is mine. Invoice 1043 returned another customer's name, email and total.
There is no rate limiting on enumeration.
