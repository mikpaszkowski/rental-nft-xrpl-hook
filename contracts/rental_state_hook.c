
#include "hookapi.h"
#include <stdint.h>

#define UNIX_TIMESTAMP_OFFSET 946684800
#define DAY_IN_SECONDS 86400

//ERRORS
#define LAST_CLOSED_LEDGER_BUFF 10
#define ERROR_URITOKEN_OCCUPIED 20
#define ERROR_INVALID_TX_MEMOS 1
#define ERROR_MISSING_HOOK_PARAM 2
#define ERROR_MISSING_DESTINATION_ACC 3
#define INTERNAL_HOOK_STATE_MUTATION_ERROR 4

int64_t hook(uint32_t ctx) {

    TRACESTR("HOOK FIRED")

    uint8_t TX_PARAM_RENTAL_DEADLINE_NAME[] = {'R', 'E', 'N', 'T', 'A', 'L', 'D', 'E', 'A', 'D', 'L', 'I', 'N', 'E'};
    uint8_t TX_PARAM_RENTAL_AMOUNT_NAME[] = {'R', 'E', 'N', 'T', 'A', 'L', 'A', 'M', 'O', 'U', 'N', 'T'};
    uint32_t RENTAL_IN_PROGRESS_AMOUNT_KEY[] = {112};

    //READING VARIABLES FROM STATE, TX and HOOKS CONTEXT to be used further
    uint32_t NUM_OF_RENTALS[1];
    int64_t NUM_OF_RENTALS_LOOKUP = state(SBUF(NUM_OF_RENTALS), SBUF(RENTAL_IN_PROGRESS_AMOUNT_KEY));
    TRACEVAR(NUM_OF_RENTALS[0]);

    uint8_t URITOKEN_TX_VALUE[32];
    int64_t URITOKEN_TX_LOOKUP = otxn_field((uint32_t) (uintptr_t) URITOKEN_TX_VALUE, 32, sfURITokenID);
    TRACEHEX(URITOKEN_TX_VALUE);

    int8_t URITOKEN_STORE_VALUE[34];
    int64_t URITOKEN_STORE_LOOKUP = state(SBUF(URITOKEN_STORE_VALUE), SBUF(URITOKEN_TX_VALUE));
    TRACEHEX(URITOKEN_STORE_LOOKUP);

    int64_t RENTAL_DEADLINE_TS_VALUE = float_int(*((int64_t *) URITOKEN_STORE_VALUE), 0, 1);
    TRACEVAR(RENTAL_DEADLINE_TS_VALUE)

    int64_t TX_TYPE = otxn_type();

    int64_t LEDGER_LAST_TIME_TS = ledger_last_time() + UNIX_TIMESTAMP_OFFSET;
    TRACEVAR(LEDGER_LAST_TIME_TS);

    TRACEHEX(TX_PARAM_RENTAL_DEADLINE_NAME)
    uint8_t otxn_param_value_deadline[8];
    int64_t otxn_param_value_deadline_lookup = otxn_param(SBUF(otxn_param_value_deadline),
                                                          SBUF(TX_PARAM_RENTAL_DEADLINE_NAME));
    TRACEHEX(otxn_param_value_deadline);
    int64_t otxn_deadline_value = float_int(*((int64_t *) otxn_param_value_deadline), 0, 1);
    TRACEVAR(otxn_deadline_value);

    // ACCOUNT: Origin Tx Account
    uint8_t otx_acc[20];
    otxn_field(SBUF(otx_acc), sfAccount);

    // ACCOUNT: Hook Account
    uint8_t hook_acc[20];
    hook_account(SBUF(hook_acc));

    int is_tx_outcoming = 0;
    BUFFER_EQUAL(is_tx_outcoming, hook_acc, otx_acc, 20);
    if (!is_tx_outcoming) {
        TRACESTR("Incoming TX on Account")
    } else {
        TRACESTR("Outcoming TX on Account")
    }

    if (TX_TYPE == ttURITOKEN_CANCEL_SELL_OFFER && URITOKEN_STORE_LOOKUP > 0) {
        rollback(SBUF("[ONGOING RENTALS]: Return offers waits for owner to be accepted"), 10);
    }
    if (TX_TYPE == ttURITOKEN_BURN && URITOKEN_STORE_LOOKUP > 0) {
        rollback(SBUF("[ONGOING RENTALS]: Cannot burn URIToken which is in ongoing rental process"), 10);
    }

    if (TX_TYPE == ttACCOUNT_DELETE || TX_TYPE == ttHOOK_SET) {
        TRACESTR("Reading number of rentals in progress from state");
        if (NUM_OF_RENTALS[0] > 0) {
            rollback(SBUF("[ONGOING RENTALS]: cannot mutate hook, delete account or burn rented token"), 10);
        } else if (NUM_OF_RENTALS[0] < 0) {
            TRACESTR("No rentals on this account yet");
        }
        if (TX_TYPE == ttACCOUNT_DELETE) TRACESTR("[NO ONGOING RENTALS]: AccountDelete tx accepted");
        if (TX_TYPE == ttACCOUNT_DELETE) TRACESTR("[NO ONGOING RENTALS]: SetHook tx accepted");
        accept(SBUF("Tx accepted"), (uint64_t) (uintptr_t) 0);
    }

    //Token owner accepted the return offer
    if (TX_TYPE == ttURITOKEN_BUY && !is_tx_outcoming && URITOKEN_STORE_LOOKUP > 0 && NUM_OF_RENTALS[0] > 0) {
        TRACESTR("URIToken should be removed from the store");
        if (state_set(0, 0, SBUF(URITOKEN_TX_VALUE)) < 0) {
            rollback(SBUF("[INTERNAL HOOK STATE ERROR]:  Could not remove the URIToken from the state"),
                     INTERNAL_HOOK_STATE_MUTATION_ERROR);
        } else {
            TRACESTR("URIToken removed from the store");
        }
        TRACEVAR(NUM_OF_RENTALS[0])
        if (NUM_OF_RENTALS[0] <= 0) {
            NUM_OF_RENTALS[0] = 0;
        } else {
            NUM_OF_RENTALS[0]--;
        }
        TRACEVAR(NUM_OF_RENTALS[0]);
        if (state_set(SBUF(NUM_OF_RENTALS), SBUF(RENTAL_IN_PROGRESS_AMOUNT_KEY)) < 0) {
            rollback(SBUF("[INTERNAL HOOK STATE ERROR]: Could not decrement number of rentals in state"),
                     INTERNAL_HOOK_STATE_MUTATION_ERROR);
        } else {
            accept(SBUF("Finish of rental process. Num of rentals decremented, Tx accepted"), (uint64_t) (uintptr_t) 0);
        }
        _g(1, 1);
        return 0;
    } else if (TX_TYPE == ttURITOKEN_BUY && URITOKEN_STORE_LOOKUP <= 0) {
        TRACESTR("SAVE URIToken to the store");
        int64_t savedURITokenLength = state_set(SBUF(otxn_param_value_deadline), SBUF(URITOKEN_TX_VALUE));
        if (savedURITokenLength < 0) {
            rollback(SBUF("[INTERNAL HOOK STATE ERROR]: URIToken save failure"), 1);
        } else {
            if (NUM_OF_RENTALS_LOOKUP < 0) {
                NUM_OF_RENTALS[0] = 1;
            } else {
                NUM_OF_RENTALS[0]++;
            }
            TRACEVAR(NUM_OF_RENTALS[0]);
            if (state_set(SBUF(NUM_OF_RENTALS), SBUF(RENTAL_IN_PROGRESS_AMOUNT_KEY)) < 0) {
                rollback(SBUF("[TX REJECTED]: Could not mutate num of rentals value"), 1);
            }
            accept(SBUF("New NFTokenID saved to the store, Tx accepted"), (uint64_t) (uintptr_t) 0);
        }
        _g(1, 1);
        return 0;
    }

    uint8_t otxn_param_value_amount[8];
    int64_t otxn_param_value_amount_lookup = otxn_param(SBUF(otxn_param_value_amount),
                                                        SBUF(TX_PARAM_RENTAL_AMOUNT_NAME));
    TRACEHEX(otxn_param_value_amount);
    uint64_t otxn_amount_value = float_int(*((int64_t *) otxn_param_value_amount), 6, 1);
    TRACEVAR(otxn_amount_value);

    //check if rental context is present
    int DEADLINE_TIME_PRESENT = otxn_param_value_deadline_lookup > 0 && otxn_deadline_value > 0;
    int RENTAL_TOTAL_AMOUNT_PRESENT = otxn_param_value_amount_lookup > 0 != 0 && otxn_amount_value > 0;

    if (!DEADLINE_TIME_PRESENT || !RENTAL_TOTAL_AMOUNT_PRESENT) {
        // ***** RENTAL CONTEXT MISSING *****
        //probably non-rental incoming transaction
        if (URITOKEN_STORE_LOOKUP > 0) {
            rollback(SBUF("[ONGOING RENTALS]: URIToken is already in ongoing rental process"), ERROR_URITOKEN_OCCUPIED);
        } else {
            accept(SBUF("[TX ACCEPTED]: Non-rental tx accepted"), (uint64_t) (uintptr_t) 0);
        }
    } else {
        // ***** RENTAL CONTEXT VALID *****
        //Transaction parameters validation
        uint8_t foreignRenterURIToken[32];
        int64_t foreignRenterURIToken_lookup = -1;
        if (TX_TYPE == ttURITOKEN_CREATE_SELL_OFFER) {

            //reading param from incoming transaction
            uint8_t foreignAccountNS[32];
            uint8_t ns_param_name[] = {'F', 'O', 'R', 'E', 'I', 'G', 'N', 'N', 'S'};
            int64_t foreignRenterAccountNamespace_lookup = otxn_param(SBUF(foreignAccountNS), SBUF(ns_param_name));
            TRACEHEX(foreignAccountNS);

            uint8_t foreignAcc[20];
            uint8_t account_param_name[] = {'F', 'O', 'R', 'E', 'I', 'G', 'N', 'A', 'C', 'C'};
            int64_t renterAccountId_lookup = otxn_param(SBUF(foreignAcc), SBUF(account_param_name));
            TRACEHEX(foreignAcc);

            if ((foreignRenterAccountNamespace_lookup < 0 || renterAccountId_lookup < 0) &&
                URITOKEN_STORE_LOOKUP > 0) {
                TRACESTR("[TX REJECTED]: No provided hook parameters for \"foreignAccountNS\" or \"foreignAcc\"");
                rollback(SBUF("[TX REJECTED]: Hook parameter (renterNS or renterAccId) missing"),
                         ERROR_MISSING_HOOK_PARAM);
            }

            uint8_t SELL_OFFER_DESTINATION_ACC[20];
            TRACESTR("BEFORE");
            int64_t SELL_OFFER_DESTINATION_ACC_LOOKUP = otxn_field(SBUF(SELL_OFFER_DESTINATION_ACC), sfDestination);
            TRACEHEX(SELL_OFFER_DESTINATION_ACC);
            TRACEHEX(SELL_OFFER_DESTINATION_ACC_LOOKUP);
            if (SELL_OFFER_DESTINATION_ACC_LOOKUP < 0) {
                TRACESTR("[TX REJECTED]: Destination field is required in URITokenCreateSellOffer");
                rollback(SBUF("[TX REJECTED]: URITokenCreateSellOffer tx is not complete: missing Destination"),
                         ERROR_MISSING_DESTINATION_ACC);
            }
            foreignRenterURIToken_lookup = state_foreign(SBUF(foreignRenterURIToken), SBUF(URITOKEN_TX_VALUE),
                                                         SBUF(foreignAccountNS),
                                                         SBUF(foreignAcc));
            TRACEHEX(foreignRenterURIToken_lookup);
            TRACEHEX(foreignRenterURIToken);
        }

        int INVALID_DEADLINE_TIME = 0;
        int INVALID_TOTAL_AMOUNT = 0;

        int64_t MIN_DEADLINE_TIMESTAMP = LEDGER_LAST_TIME_TS + LAST_CLOSED_LEDGER_BUFF + DAY_IN_SECONDS;
        TRACEVAR(MIN_DEADLINE_TIMESTAMP);
        TRACEVAR(foreignRenterURIToken_lookup)
        if ((otxn_deadline_value < MIN_DEADLINE_TIMESTAMP && foreignRenterURIToken_lookup < 0) ||
            (URITOKEN_STORE_LOOKUP > 0 && RENTAL_DEADLINE_TS_VALUE != otxn_deadline_value &&
             foreignRenterURIToken_lookup > 0 && is_tx_outcoming)) {
            INVALID_DEADLINE_TIME = 1;
        }

        //CHECKING IF rental_total_amount is valid
        uint8_t otxn_field_amount_value[8];
        int64_t otxn_field_amount_lookup = otxn_field(otxn_field_amount_value, 8, sfAmount);
        TRACEHEX(otxn_field_amount_value);
        uint64_t otxn_field_amount_drops = AMOUNT_TO_DROPS(otxn_field_amount_value);
        TRACEVAR(otxn_field_amount_drops); // <- value
        TRACEVAR(otxn_amount_value); // <- value

        if ((otxn_field_amount_drops <= 0 && foreignRenterURIToken_lookup < 0) ||
            (otxn_field_amount_drops != 0 && foreignRenterURIToken_lookup > 0 && is_tx_outcoming)) {
            INVALID_TOTAL_AMOUNT = 1;
        }

        //TX ROLLBACK because of INVALID MEMO DATA
        if (INVALID_TOTAL_AMOUNT || INVALID_DEADLINE_TIME) {
            TRACESTR("[TX REJECTED]: Invalid rental memo data");
            rollback(SBUF("[TX REJECTED]: Invalid rental tx memos"), ERROR_INVALID_TX_MEMOS);
        } else {
            if (TX_TYPE == ttURITOKEN_CREATE_SELL_OFFER) {
                if (URITOKEN_STORE_LOOKUP > 0) {
                    if (foreignRenterURIToken_lookup < 0) {
                        TRACESTR("URIToken already present in the store");
                        rollback(SBUF("[ONGOING RENTALS]: URIToken is already in ongoing rental process"),
                                 ERROR_URITOKEN_OCCUPIED);
                    }
                    //check if the rental termination rules has been fulfilled
                    TRACEVAR(NUM_OF_RENTALS[0]);
                    TRACEVAR(foreignRenterURIToken_lookup);
                    TRACEVAR(LEDGER_LAST_TIME_TS + LAST_CLOSED_LEDGER_BUFF)
                    if (RENTAL_DEADLINE_TS_VALUE > LEDGER_LAST_TIME_TS + LAST_CLOSED_LEDGER_BUFF) {
                        TRACESTR("URIToken rental condition in progress.");
                        rollback(SBUF("[ONGOING RENTALS]: URIToken is already in ongoing rental process"),
                                 ERROR_URITOKEN_OCCUPIED);
                    }
                    if (foreignRenterURIToken_lookup > 0 && NUM_OF_RENTALS[0] > 0) {
                        TRACESTR("URIToken rental condition fulfilled. Token ready to be returned");
                        accept(SBUF("[TX ACCEPTED]: URIToken return offer accepted"), 0);
                    } else {
                        TRACESTR("URIToken return conditions not fulfilled. Rental process has not finished yet.");
                        rollback(SBUF("[ONGOING RENTALS]: URIToken is already in ongoing rental process"),
                                 ERROR_URITOKEN_OCCUPIED);
                    }
                } else {
                    TRACESTR("URIToken not present in the store. Ready to be rented.");
                    accept(SBUF("[TX ACCEPTED]: URIToken rental start offer accepted"), 0);
                }
            }
        }
    }
    accept(SBUF("Tx accepted"), (uint64_t) (uintptr_t) 0);
    _g(1, 1);
    return 0;
}