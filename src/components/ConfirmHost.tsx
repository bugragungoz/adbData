import { confirmQueue } from '../state/dialogs';
import { Button } from './Button';
import { Dialog } from './Dialog';

/** Shows the oldest pending question. Escape, the scrim and Cancel all answer "no". */
export function ConfirmHost() {
  const req = confirmQueue.value[0];
  if (!req) return null;
  return (
    <Dialog
      title={req.title}
      size="question"
      onClose={() => req.resolve(false)}
      describedBy={`confirm-body-${req.id}`}
      initialFocus="[data-cancel]"
      actions={
        <>
          <Button data-cancel onClick={() => req.resolve(false)}>
            {req.cancelLabel}
          </Button>
          <Button variant={req.danger ? 'danger' : 'primary'} data-confirm onClick={() => req.resolve(true)}>
            {req.confirmLabel}
          </Button>
        </>
      }
    >
      <p class="bg-dialog-text" id={`confirm-body-${req.id}`}>
        {req.body}
      </p>
    </Dialog>
  );
}
