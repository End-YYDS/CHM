import { Button } from './components/ui/button';

function App() {
  return (
    <>
      <h1 className='text-3xl text-cyan-400'>Hello World</h1>
      <Button
        onClick={() => {
          alert('Clicked Me');
        }}
      >
        ClickMe
      </Button>
    </>
  );
}

export default App;
