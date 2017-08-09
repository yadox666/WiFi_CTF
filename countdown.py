import sys

try:
    import pyglet
except Exception as e:
    print "Have to install pyglet library for Python!"
    try:
        os.system("pip install pyglet")
	import pyglet
    except OsError as e:
        print "Could not auto install it! Please try yourself!"

window = pyglet.window.Window(fullscreen=True)
COUNTDOWN = int(sys.argv[1])

class Timer(object):
    def __init__(self):
        self.start = '9:99:99'
        self.label_count = pyglet.text.Label(self.start, font_size=200, x=window.width//2, y=window.height//2, anchor_x='center', anchor_y='center')
        self.reset()

    def reset(self):
        self.time = COUNTDOWN
        self.running = False
        self.label_count.text = self.start
        self.label_count.color = (255, 255, 255, 255)

    def update(self, dt):
        if self.running:
            self.time -= dt
            m, s = divmod(self.time, 60)
            h, m = divmod(m, 60)
	    self.label_count.text = "%d:%02d:%02d" % (h, m, s)
            if m < 5:
                self.label_count.color = (180, 0, 0, 255)
            if m < 0:
                self.running = False
                self.label_count.text = 'BOOM!!!'


@window.event
def on_key_press(symbol, modifiers):
    if symbol == pyglet.window.key.SPACE:
        if timer.running:
            timer.running = False
        else:
            timer.running = True
    elif symbol == pyglet.window.key.ESCAPE:
        window.close()

@window.event
def on_draw():
    window.clear()
    timer.label_count.draw()
    timer.running = True

timer = Timer()
pyglet.clock.schedule_interval(timer.update, 1)
pyglet.app.run()
