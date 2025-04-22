package unit.worker;

import com.opencbs.core.accounting.services.AccountService;
import com.opencbs.core.accounting.services.AccountingEntryService;
import com.opencbs.core.officedocuments.services.PrintingFormService;
import com.opencbs.core.workers.AccountingEntryWorker;
import com.opencbs.core.workers.impl.AccountingEntryWorkerImpl;
import org.junit.jupiter.api.BeforeEach;
import org.mockito.Mock;

//@RunWith(MockitoJUnitRunner.class)
public class AccountingEntryWorkerTests {

    @Mock
    private AccountingEntryService accountingEntryService;

    @Mock
    private AccountService accountService;

    @Mock
    private PrintingFormService printingFormService;

    @BeforeEach
    public void init() {
        AccountingEntryWorker accountingEntryWorker = new AccountingEntryWorkerImpl(
                accountingEntryService, accountService, printingFormService
        );
    }
}
